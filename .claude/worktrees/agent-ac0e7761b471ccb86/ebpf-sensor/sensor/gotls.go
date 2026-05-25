// sensor/gotls.go — Go TLS Uprobe Loader
// Build constraint: Linux only — depends on bpf2go-generated GoTlsObjects.
//
// Implements the tls-uprobe-calculator skill in pure Go:
//   1. Parse the ELF symbol table of a running Go binary to find the virtual
//      addresses of crypto/tls.(*Conn).Write and crypto/tls.(*Conn).Read.
//   2. Walk /proc/*/exe to auto-discover candidate Go binaries.
//   3. Load the bpf2go-generated GoTlsObjects and attach uprobes at the
//      computed symbol offsets.
//   4. Read events from the ring buffer and publish them to Redis.
//
// Graceful degradation: if no suitable Go binary is found, or if the ELF
// parse fails, or if the BPF object fails to load — log and return without
// crashing the sensor. The kprobe and OpenSSL probe paths continue unaffected.
//go:build linux

package sensor

import (
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"go.uber.org/zap"
)

// ErrGoTLSSymbolNotFound is returned by FindGoTLSSymbols when one or both of
// the required crypto/tls symbols are absent from the binary's symbol table.
var ErrGoTLSSymbolNotFound = errors.New("crypto/tls symbols not found in ELF binary")

// goTLSSymbolWrite is the full Go symbol name for the TLS write path.
const goTLSSymbolWrite = "crypto/tls.(*Conn).Write"

// goTLSSymbolRead is the full Go symbol name for the TLS read path.
const goTLSSymbolRead = "crypto/tls.(*Conn).Read"

// gopclntabSection is the ELF section present in all Go binaries that
// contains the runtime's PC-to-line-number table. Its presence is a
// reliable indicator that a binary was compiled with the Go toolchain.
const gopclntabSection = ".gopclntab"

// FindGoTLSSymbols parses the ELF symbol table of binaryPath and returns the
// virtual addresses of crypto/tls.(*Conn).Write and crypto/tls.(*Conn).Read.
//
// The returned addresses are suitable for use with link.UprobeOptions{Address: addr}
// when cilium/ebpf's symbol-name resolution fails (e.g. stripped binary).
//
// Returns ErrGoTLSSymbolNotFound if either symbol is absent.
func FindGoTLSSymbols(binaryPath string) (writeAddr, readAddr uint64, err error) {
	f, err := elf.Open(binaryPath)
	if err != nil {
		return 0, 0, fmt.Errorf("elf.Open %s: %w", binaryPath, err)
	}
	defer f.Close()

	// Validate that the binary is actually a Go binary by checking for the
	// .gopclntab section before attempting symbol lookup. This prevents us
	// from wasting time on non-Go binaries found in /proc.
	if f.Section(gopclntabSection) == nil {
		return 0, 0, fmt.Errorf("%s: missing %s section — not a Go binary", binaryPath, gopclntabSection)
	}

	// Walk the symbol table. elf.File.Symbols() returns ([]elf.Symbol, error);
	// a missing symbol table returns an error wrapping elf.ErrNoSymbols.
	symbols, err := f.Symbols()
	if err != nil {
		return 0, 0, fmt.Errorf("reading ELF symbols from %s: %w", binaryPath, err)
	}

	for _, sym := range symbols {
		switch sym.Name {
		case goTLSSymbolWrite:
			writeAddr = sym.Value
		case goTLSSymbolRead:
			readAddr = sym.Value
		}
		// Early exit once both symbols are found.
		if writeAddr != 0 && readAddr != 0 {
			return writeAddr, readAddr, nil
		}
	}

	if writeAddr == 0 || readAddr == 0 {
		return 0, 0, fmt.Errorf("%s: %w (write=0x%x read=0x%x)",
			binaryPath, ErrGoTLSSymbolNotFound, writeAddr, readAddr)
	}
	return writeAddr, readAddr, nil
}

// findGoTLSBinary finds a suitable Go binary to hook for crypto/tls traffic.
//
// Resolution order:
//  1. GOTLS_BINARY_PATH env var — operator-specified binary takes priority.
//  2. Walk /proc/*/exe — find any running process whose main executable is a
//     Go binary that exports the required crypto/tls symbols.
//
// Returns the path to the first viable binary, or an error if none is found.
// Skips non-numeric /proc entries and broken symlinks without logging noise.
func findGoTLSBinary(log *zap.Logger) (string, error) {
	// 1. Operator override.
	if override := os.Getenv("GOTLS_BINARY_PATH"); override != "" {
		log.Info("using GOTLS_BINARY_PATH override", zap.String("path", override))
		if _, _, err := FindGoTLSSymbols(override); err != nil {
			return "", fmt.Errorf("GOTLS_BINARY_PATH %s: %w", override, err)
		}
		return override, nil
	}

	// 2. Auto-discover running Go processes from /proc.
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return "", fmt.Errorf("reading /proc: %w", err)
	}

	for _, entry := range entries {
		// Only numeric entries correspond to process directories.
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}

		exePath := filepath.Join("/proc", entry.Name(), "exe")
		target, err := os.Readlink(exePath)
		if err != nil {
			// Process may have exited between ReadDir and Readlink — ignore.
			continue
		}

		// Deduplicate: skip the current binary (this sensor process) to avoid
		// self-uprobing, which would generate recursive events.
		selfExe, _ := os.Readlink("/proc/self/exe")
		if target == selfExe {
			continue
		}

		// Skip paths that obviously cannot be Go binaries (kernel threads, etc.)
		if !strings.HasPrefix(target, "/") {
			continue
		}

		_, _, err = FindGoTLSSymbols(target)
		if err != nil {
			// Not a Go binary or missing symbols — try next process.
			continue
		}

		log.Info("discovered Go binary for TLS uprobes",
			zap.String("pid", entry.Name()),
			zap.String("exe", target),
		)
		return target, nil
	}

	return "", fmt.Errorf("no running Go binary with crypto/tls symbols found in /proc")
}

// RunGoTLSPrograms loads the bpf2go-generated GoTlsObjects, attaches uprobes
// to the crypto/tls.(*Conn).Write and Read methods of a discovered Go binary,
// and reads events from the ring buffer, publishing to Redis.
//
// Called as a goroutine from liveSensor.Run(). All errors are logged and cause
// this function to return without crashing — same graceful degradation pattern
// as the OpenSSL uprobe path in runSensorPrograms.
func (s *liveSensor) RunGoTLSPrograms(ctx context.Context) {
	log := s.log.Named("gotls")

	// Locate a suitable Go binary. This is best-effort.
	binaryPath, err := findGoTLSBinary(log)
	if err != nil {
		log.Warn("Go TLS uprobes disabled — no target binary found", zap.Error(err))
		return
	}

	// Pre-compute symbol addresses for fallback (in case name-based lookup fails).
	writeAddr, readAddr, err := FindGoTLSSymbols(binaryPath)
	if err != nil {
		log.Warn("failed to read Go TLS symbol addresses", zap.Error(err))
		return
	}

	log.Info("Go TLS symbol addresses resolved",
		zap.String("binary", binaryPath),
		zap.Uint64("Write", writeAddr),
		zap.Uint64("Read", readAddr),
	)

	// Load the bpf2go-generated object file (compiled from bpf/go_tls_trace.c).
	// GoTlsObjects and LoadGoTlsObjects are generated at build time.
	gtObjs := GoTlsObjects{}
	if err := LoadGoTlsObjects(&gtObjs, &ebpf.CollectionOptions{}); err != nil {
		log.Error("failed to load GoTls eBPF objects", zap.Error(err))
		return
	}
	defer gtObjs.Close()

	// Open the target executable for uprobe attachment.
	ex, err := link.OpenExecutable(binaryPath)
	if err != nil {
		log.Error("failed to open Go binary for uprobes", zap.String("path", binaryPath), zap.Error(err))
		return
	}

	var closers []func()

	// ── Attach uprobe/gotls_write ──────────────────────────────────────────────
	// Try symbol-name lookup first (works for non-stripped binaries).
	// Fall back to computed offset if the name contains characters that
	// cilium/ebpf cannot pass to the kernel's uprobe API directly.
	upWrite, err := ex.Uprobe(goTLSSymbolWrite, gtObjs.UprobeGotlsWrite, nil)
	if err != nil {
		log.Warn("symbol-name uprobe failed for Write, trying address fallback",
			zap.Error(err))
		upWrite, err = ex.Uprobe("", gtObjs.UprobeGotlsWrite,
			&link.UprobeOptions{Address: writeAddr})
		if err != nil {
			log.Warn("failed to attach uprobe for crypto/tls Write", zap.Error(err))
		}
	}
	if upWrite != nil {
		closers = append(closers, func() { upWrite.Close() })
		log.Info("uprobe attached: crypto/tls.(*Conn).Write", zap.String("binary", binaryPath))
	}

	// ── Attach uprobe/gotls_read_enter ─────────────────────────────────────────
	upReadEnter, err := ex.Uprobe(goTLSSymbolRead, gtObjs.UprobeGotlsReadEnter, nil)
	if err != nil {
		log.Warn("symbol-name uprobe failed for Read enter, trying address fallback",
			zap.Error(err))
		upReadEnter, err = ex.Uprobe("", gtObjs.UprobeGotlsReadEnter,
			&link.UprobeOptions{Address: readAddr})
		if err != nil {
			log.Warn("failed to attach uprobe for crypto/tls Read (entry)", zap.Error(err))
		}
	}
	if upReadEnter != nil {
		closers = append(closers, func() { upReadEnter.Close() })
		log.Info("uprobe attached: crypto/tls.(*Conn).Read (entry)", zap.String("binary", binaryPath))
	}

	// ── Attach uretprobe/gotls_read_exit ──────────────────────────────────────
	upReadExit, err := ex.Uretprobe(goTLSSymbolRead, gtObjs.UprobeGotlsReadExit, nil)
	if err != nil {
		log.Warn("symbol-name uretprobe failed for Read exit, trying address fallback",
			zap.Error(err))
		upReadExit, err = ex.Uretprobe("", gtObjs.UprobeGotlsReadExit,
			&link.UprobeOptions{Address: readAddr})
		if err != nil {
			log.Warn("failed to attach uretprobe for crypto/tls Read (exit)", zap.Error(err))
		}
	}
	if upReadExit != nil {
		closers = append(closers, func() { upReadExit.Close() })
		log.Info("uretprobe attached: crypto/tls.(*Conn).Read (exit)", zap.String("binary", binaryPath))
	}

	defer func() {
		for _, closeFn := range closers {
			closeFn()
		}
	}()

	if len(closers) == 0 {
		log.Warn("no Go TLS probes could be attached — GoTLS monitoring disabled")
		return
	}

	// ── Ring buffer reader ─────────────────────────────────────────────────────
	rd, err := ringbuf.NewReader(gtObjs.Events)
	if err != nil {
		log.Error("failed to open GoTls ring buffer", zap.Error(err))
		return
	}
	defer rd.Close()

	log.Info("GoTls ring buffer open — streaming Go TLS events to Redis",
		zap.String("stream", s.cfg.RedisStream),
	)

	go func() {
		<-ctx.Done()
		rd.Close()
	}()

	for {
		record, err := rd.Read()
		if err != nil {
			if ctx.Err() != nil {
				return // clean shutdown
			}
			log.Warn("GoTls ring buffer read error", zap.Error(err))
			continue
		}

		evt, err := parseSensorEvent(record.RawSample)
		if err != nil {
			log.Warn("failed to parse GoTls sensor event", zap.Error(err))
			continue
		}

		// Observe the path in the drift engine for change-point detection.
		if evt.Path != "" {
			s.drift.Observe(evt.Path)
		}

		if err := s.publishSensorEvent(ctx, evt); err != nil {
			log.Error("failed to publish GoTls event to Redis", zap.Error(err))
		}
	}
}
