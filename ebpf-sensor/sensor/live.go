// sensor/live.go — Live eBPF sensor implementation.
//
// Loads the bpf2go-generated eBPF objects (compiled from bpf/http_trace.c,
// bpf/sensor.c, and bpf/go_tls_trace.c), attaches probes, reads events from
// the ring buffers, and publishes structured JSON events to Redis Streams.
//
// Requirements:
//   - Linux kernel >= 5.8  (BPF_MAP_TYPE_RINGBUF)
//   - CAP_BPF + CAP_SYS_ADMIN (or run as root)
//   - SENSOR_MODE=live

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target amd64 -cflags "-O2 -g -Wall -Werror -D__TARGET_ARCH_x86" HttpTrace ../bpf/http_trace.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target amd64 -cflags "-O2 -g -Wall -Werror -D__TARGET_ARCH_x86" Sensor ../bpf/sensor.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target amd64 -cflags "-O2 -g -Wall -Werror -D__TARGET_ARCH_x86" GoTls ../bpf/go_tls_trace.c

//go:build linux

package sensor

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// HttpEvent is the Go representation of an event emitted by the eBPF program.
// Published to Redis as JSON.
type HttpEvent struct {
	PID         uint32 `json:"pid"`
	TID         uint32 `json:"tid"`
	Method      string `json:"method"`
	Path        string `json:"path"`
	StatusCode  uint16 `json:"status_code"`
	TimestampNs int64  `json:"timestamp_ns"`
}

// httpEventC mirrors the C struct http_event_t defined in bpf/http_trace.c.
//
// Layout (x86-64 little-endian, clang default packing):
//
//	__u32 pid;           offset  0, 4 bytes
//	__u32 tid;           offset  4, 4 bytes
//	__u64 timestamp_ns;  offset  8, 8 bytes
//	__u16 status_code;   offset 16, 2 bytes
//	char  method[8];     offset 18, 8 bytes
//	char  path[128];     offset 26, 128 bytes
//	tail padding         6 bytes  → sizeof = 160
//
// This struct is only used with encoding/binary.Read; field order must match.
type httpEventC struct {
	Pid         uint32
	Tid         uint32
	TimestampNs uint64
	StatusCode  uint16
	Method      [8]byte
	Path        [128]byte
	_           [6]byte // tail padding to reach 160-byte alignment boundary
}

// eventSize is the canonical size of http_event_t including tail padding.
// Must match sizeof(struct http_event_t) as reported by clang.
const eventSize = 160

// liveSensor runs actual eBPF programs on a Linux kernel >= 5.8.
type liveSensor struct {
	cfg      Config
	log      *zap.Logger
	rdb      *redis.Client
	drift    *DriftEngine
	reporter *BrainReporter // forwards events to hosted brain in company install mode
}

func newLiveSensor(cfg Config, log *zap.Logger) (*liveSensor, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
	})

	// Fail fast: verify Redis is reachable before the sensor starts emitting events.
	pingCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := rdb.Ping(pingCtx).Err(); err != nil {
		return nil, fmt.Errorf("redis not reachable at %s: %w", cfg.RedisAddr, err)
	}

	drift := NewDriftEngine(DefaultDriftConfig(), log.Named("drift"))
	reporter := NewBrainReporter(cfg, log.Named("reporter"))
	return &liveSensor{cfg: cfg, log: log, rdb: rdb, drift: drift, reporter: reporter}, nil
}

// Run starts all eBPF programs and blocks until ctx is cancelled.
//
// The kprobe/tcp_sendmsg path (http_trace.c) is non-fatal: if its eBPF object
// fails to load (e.g., CO-RE iov_iter field relocation fails on kernel >= 6.0),
// the sensor continues with syscall tracepoints + TLS uprobes from sensor.c,
// which provide equivalent or better coverage for most workloads.
func (s *liveSensor) Run(ctx context.Context) error {
	s.log.Info("Live eBPF sensor starting — removing RLIMIT_MEMLOCK")

	// Allow the process to lock unlimited memory for eBPF maps.
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}

	// Register with remote brain if BRAIN_URL is configured (company install mode).
	if s.cfg.BrainURL != "" {
		s.reporter.Register(ctx)
		s.log.Info("remote brain connection",
			zap.String("brain_url", s.cfg.BrainURL),
			zap.String("sensor_id", s.reporter.SensorID()),
			zap.Bool("connected", s.reporter.Connected()),
		)
	}

	// Start the drift detection engine. It runs until ctx is cancelled.
	go s.drift.Run(ctx, s.publishDriftAlert)

	// Launch the comprehensive sensor (tracepoints + TLS uprobes) in parallel.
	go s.runSensorPrograms(ctx)

	// Launch the Go TLS sensor (crypto/tls uprobes) in parallel.
	// Graceful: if no suitable Go binary is found, this goroutine exits silently.
	go s.RunGoTLSPrograms(ctx)

	// Launch the kprobe/tcp_sendmsg sensor in parallel.
	// Non-fatal: if the eBPF object fails to load, a warning is logged and the
	// goroutine exits, leaving the other two paths intact.
	go s.runKprobePrograms(ctx)

	// Block until the context is cancelled (SIGINT/SIGTERM).
	<-ctx.Done()
	return nil
}

// runKprobePrograms loads the HttpTrace eBPF object (compiled from http_trace.c),
// attaches kprobe/tcp_sendmsg, and streams events to Redis.
//
// Failure is non-fatal: the program logs a warning and returns without crashing
// the sensor. This handles the case where the kernel's iov_iter struct has been
// reorganised (e.g., field renamed from .iov to .__iov in kernel >= 6.0) and
// the CO-RE relocation in the eBPF loader fails at load time.
func (s *liveSensor) runKprobePrograms(ctx context.Context) {
	log := s.log.Named("kprobe")

	objs := HttpTraceObjects{}
	if err := LoadHttpTraceObjects(&objs, &ebpf.CollectionOptions{}); err != nil {
		log.Warn("kprobe/tcp_sendmsg disabled — eBPF load failed "+
			"(likely iov_iter CO-RE mismatch on kernel >= 6.0); "+
			"syscall tracepoints + TLS uprobes remain active",
			zap.Error(err))
		return
	}
	defer objs.Close()

	kp, err := link.Kprobe("tcp_sendmsg", objs.KprobeTcpSendmsg, nil)
	if err != nil {
		log.Warn("failed to attach kprobe/tcp_sendmsg", zap.Error(err))
		return
	}
	defer kp.Close()

	log.Info("kprobe attached to tcp_sendmsg")

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Error("failed to open kprobe ring buffer", zap.Error(err))
		return
	}
	// sync.Once prevents a double-close: the goroutine fires on ctx cancellation
	// to unblock rd.Read(), and defer fires when the function returns. Without
	// Once, both paths would call rd.Close(), which is not idempotent.
	var rdOnce sync.Once
	closeRd := func() { rdOnce.Do(func() { rd.Close() }) }
	defer closeRd()

	log.Info("kprobe ring buffer open — streaming events to Redis",
		zap.String("stream", s.cfg.RedisStream),
	)

	go func() {
		<-ctx.Done()
		closeRd()
	}()

	var processedCount atomic.Int64

	for {
		record, err := rd.Read()
		if err != nil {
			if ctx.Err() != nil {
				return // clean shutdown
			}
			log.Warn("kprobe ring buffer read error", zap.Error(err))
			continue
		}

		evt, err := parseRawEvent(record.RawSample)
		if err != nil {
			log.Warn("failed to parse kprobe event", zap.Error(err))
			continue
		}

		if err := s.publishEvent(ctx, evt); err != nil {
			log.Error("failed to publish kprobe event to Redis", zap.Error(err))
		}

		if evt.Path != "" {
			s.drift.Observe(evt.Path)
		}

		n := processedCount.Add(1)
		if n%1000 == 0 {
			log.Info("kprobe event throughput checkpoint", zap.Int64("total_events", n))
		}
	}
}

// parseRawEvent deserialises the binary C struct from the eBPF ring buffer.
//
// The raw bytes are a packed representation of struct http_event_t.
// We use encoding/binary (little-endian) which matches x86-64 kernel layout.
// JSON unmarshal is WRONG here — the kernel writes a C struct, not JSON.
func parseRawEvent(raw []byte) (*HttpEvent, error) {
	if len(raw) < eventSize {
		return nil, fmt.Errorf("record too short: got %d bytes, want %d", len(raw), eventSize)
	}

	var c httpEventC
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &c); err != nil {
		return nil, fmt.Errorf("binary.Read: %w", err)
	}

	return &HttpEvent{
		PID:         c.Pid,
		TID:         c.Tid,
		TimestampNs: int64(c.TimestampNs),
		StatusCode:  c.StatusCode,
		Method:      nullTermString(c.Method[:]),
		Path:        nullTermString(c.Path[:]),
	}, nil
}

// nullTermString converts a null-padded byte slice to a Go string.
func nullTermString(b []byte) string {
	return strings.TrimRight(string(b), "\x00")
}

// publishEvent marshals an HttpEvent to JSON, forwards it to the remote brain
// (if configured), and writes it to the Redis stream.
func (s *liveSensor) publishEvent(ctx context.Context, evt *HttpEvent) error {
	// Replace kernel monotonic timestamp (nanoseconds since boot) with wall-clock
	// time so consumers can correlate events across machines without boot-time offsets.
	evt.TimestampNs = time.Now().UnixNano()
	payload, err := json.Marshal(evt)
	if err != nil {
		return fmt.Errorf("json marshal: %w", err)
	}
	s.reporter.Report(ctx, payload)
	return s.rdb.XAdd(ctx, &redis.XAddArgs{
		Stream: s.cfg.RedisStream,
		Values: map[string]interface{}{"data": string(payload)},
	}).Err()
}

// publishDriftAlert marshals a DriftAlert, forwards it to the remote brain
// (if configured), and writes it to the Redis stream.
// The remediation-brain consumes drift_alert events to trigger LangGraph workflows.
func (s *liveSensor) publishDriftAlert(ctx context.Context, alert DriftAlert) error {
	payload, err := json.Marshal(alert)
	if err != nil {
		return fmt.Errorf("json marshal drift alert: %w", err)
	}
	s.reporter.ReportAlert(ctx, alert)
	return s.rdb.XAdd(ctx, &redis.XAddArgs{
		Stream: s.cfg.RedisStream,
		Values: map[string]interface{}{"data": string(payload)},
	}).Err()
}

// DriftStats returns a snapshot of all endpoint drift states.
// Called from the /drift/stats HTTP handler in main.go.
func (s *liveSensor) DriftStats() []EndpointStats {
	return s.drift.Stats()
}

// ── Comprehensive sensor (sensor.c) ──────────────────────────────────────────
// Loads and attaches the programs from bpf/sensor.c:
//   - tracepoints: sys_enter_sendto, sys_enter_recvfrom, sys_exit_recvfrom
//   - uprobes:     SSL_write entry, SSL_read entry+exit
// Runs as a goroutine alongside the kprobe/tcp_sendmsg loop.

// SensorEvent is the Go representation of sensor_event_t from bpf/sensor.c.
// Published to the same Redis stream as HttpEvent, differentiated by source/direction.
type SensorEvent struct {
	PID         uint32 `json:"pid"`
	TID         uint32 `json:"tid"`
	Method      string `json:"method"`
	Path        string `json:"path"`
	StatusCode  uint16 `json:"status_code"`
	TimestampNs int64  `json:"timestamp_ns"`
	Source      string `json:"source"`    // "plain" | "tls" | "go_tls"
	Direction   string `json:"direction"` // "egress" | "ingress"
}

// sensorEventC mirrors struct sensor_event_t defined in bpf/common.h.
//
// Layout (x86-64 little-endian, clang default packing):
//
//	__u32  pid;           offset  0,  4 bytes
//	__u32  tid;           offset  4,  4 bytes
//	__u64  timestamp_ns;  offset  8,  8 bytes
//	__u16  status_code;   offset 16,  2 bytes
//	__u8   source;        offset 18,  1 byte
//	__u8   direction;     offset 19,  1 byte
//	char   method[8];     offset 20,  8 bytes
//	char   path[128];     offset 28, 128 bytes
//	__u8   _pad[4];       offset 156, 4 bytes → sizeof = 160
type sensorEventC struct {
	Pid         uint32
	Tid         uint32
	TimestampNs uint64
	StatusCode  uint16
	Source      uint8
	Direction   uint8
	Method      [8]byte
	Path        [128]byte
	_           [4]byte // tail padding
}

const sensorEventSize = 160 // must equal sizeof(struct sensor_event_t)

// sourceString converts the C SOURCE_* constant to a human-readable string.
func sourceString(s uint8) string {
	switch s {
	case 1:
		return "tls"
	case 2:
		return "go_tls"
	default:
		return "plain"
	}
}

// directionString converts the C DIR_* constant to a human-readable string.
func directionString(d uint8) string {
	if d == 1 {
		return "ingress"
	}
	return "egress"
}

// parseSensorEvent deserialises a raw ring buffer record from sensor.c into
// a SensorEvent. The raw bytes are a C struct — binary.LittleEndian matches
// x86-64 kernel layout.
func parseSensorEvent(raw []byte) (*SensorEvent, error) {
	if len(raw) < sensorEventSize {
		return nil, fmt.Errorf("sensor record too short: got %d bytes, want %d", len(raw), sensorEventSize)
	}

	var c sensorEventC
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &c); err != nil {
		return nil, fmt.Errorf("binary.Read sensor event: %w", err)
	}

	return &SensorEvent{
		PID:         c.Pid,
		TID:         c.Tid,
		TimestampNs: int64(c.TimestampNs),
		StatusCode:  c.StatusCode,
		Source:      sourceString(c.Source),
		Direction:   directionString(c.Direction),
		Method:      nullTermString(c.Method[:]),
		Path:        nullTermString(c.Path[:]),
	}, nil
}

// findLibSSL returns the path to libssl.so on the current host by probing
// well-known locations. Returns an error if OpenSSL is not installed.
// The uprobe attachment in runSensorPrograms is skipped gracefully if this fails.
func findLibSSL() (string, error) {
	candidates := []string{
		"/usr/lib/x86_64-linux-gnu/libssl.so.3",
		"/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
		"/usr/lib/libssl.so.3",
		"/usr/lib/libssl.so.1.1",
		"/usr/local/lib/libssl.so.3",
		"/usr/local/lib/libssl.so.1.1",
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("libssl.so not found in standard locations")
}

// publishSensorEvent marshals a SensorEvent, forwards it to the remote brain
// (if configured), and writes it to the Redis stream.
func (s *liveSensor) publishSensorEvent(ctx context.Context, evt *SensorEvent) error {
	evt.TimestampNs = time.Now().UnixNano()
	payload, err := json.Marshal(evt)
	if err != nil {
		return fmt.Errorf("json marshal sensor event: %w", err)
	}
	s.reporter.Report(ctx, payload)
	return s.rdb.XAdd(ctx, &redis.XAddArgs{
		Stream: s.cfg.RedisStream,
		Values: map[string]interface{}{"data": string(payload)},
	}).Err()
}

// runSensorPrograms loads SensorObjects (generated from bpf/sensor.c by bpf2go),
// attaches syscall tracepoints and OpenSSL uprobes, and reads events from the
// ring buffer, publishing each to Redis.
//
// Called as a goroutine from Run(). Errors are logged but do not crash the
// main sensor loop — the kprobe/tcp_sendmsg path continues regardless.
// TLS uprobe attachment is skipped gracefully if libssl is not present.
func (s *liveSensor) runSensorPrograms(ctx context.Context) {
	log := s.log.Named("sensor2")

	sObjs := SensorObjects{}
	if err := LoadSensorObjects(&sObjs, &ebpf.CollectionOptions{}); err != nil {
		log.Error("failed to load sensor eBPF objects — tracepoints+uprobes disabled", zap.Error(err))
		return
	}
	defer sObjs.Close()

	var closers []func()

	// ── Syscall tracepoints ────────────────────────────────────────────────────

	tpSend, err := link.Tracepoint("syscalls", "sys_enter_sendto", sObjs.TpSendto, nil)
	if err != nil {
		log.Warn("failed to attach tracepoint sys_enter_sendto", zap.Error(err))
	} else {
		closers = append(closers, func() { tpSend.Close() })
		log.Info("tracepoint attached: sys_enter_sendto")
	}

	tpRecvEnter, err := link.Tracepoint("syscalls", "sys_enter_recvfrom", sObjs.TpEnterRecvfrom, nil)
	if err != nil {
		log.Warn("failed to attach tracepoint sys_enter_recvfrom", zap.Error(err))
	} else {
		closers = append(closers, func() { tpRecvEnter.Close() })
		log.Info("tracepoint attached: sys_enter_recvfrom")
	}

	tpRecvExit, err := link.Tracepoint("syscalls", "sys_exit_recvfrom", sObjs.TpExitRecvfrom, nil)
	if err != nil {
		log.Warn("failed to attach tracepoint sys_exit_recvfrom", zap.Error(err))
	} else {
		closers = append(closers, func() { tpRecvExit.Close() })
		log.Info("tracepoint attached: sys_exit_recvfrom")
	}

	// ── OpenSSL uprobes ───────────────────────────────────────────────────────
	// Graceful: if libssl is not installed, log and continue with tracepoints only.

	libsslPath, err := findLibSSL()
	if err != nil {
		log.Warn("libssl not found — TLS uprobe capture disabled", zap.Error(err))
	} else {
		ex, err := link.OpenExecutable(libsslPath)
		if err != nil {
			log.Warn("failed to open libssl for uprobes", zap.String("path", libsslPath), zap.Error(err))
		} else {
			upSSLWrite, err := ex.Uprobe("SSL_write", sObjs.UprobeSslWrite, nil)
			if err != nil {
				log.Warn("failed to attach uprobe SSL_write", zap.Error(err))
			} else {
				closers = append(closers, func() { upSSLWrite.Close() })
				log.Info("uprobe attached: SSL_write", zap.String("lib", libsslPath))
			}

			upSSLReadEnter, err := ex.Uprobe("SSL_read", sObjs.UprobeSslReadEnter, nil)
			if err != nil {
				log.Warn("failed to attach uprobe SSL_read (entry)", zap.Error(err))
			} else {
				closers = append(closers, func() { upSSLReadEnter.Close() })
				log.Info("uprobe attached: SSL_read (entry)", zap.String("lib", libsslPath))
			}

			upSSLReadExit, err := ex.Uretprobe("SSL_read", sObjs.UprobeSslReadExit, nil)
			if err != nil {
				log.Warn("failed to attach uretprobe SSL_read (exit)", zap.Error(err))
			} else {
				closers = append(closers, func() { upSSLReadExit.Close() })
				log.Info("uretprobe attached: SSL_read (exit)", zap.String("lib", libsslPath))
			}
		}
	}

	defer func() {
		for _, closeFn := range closers {
			closeFn()
		}
	}()

	// ── Ring buffer reader ─────────────────────────────────────────────────────

	rd, err := ringbuf.NewReader(sObjs.Events)
	if err != nil {
		log.Error("failed to open sensor ring buffer", zap.Error(err))
		return
	}
	var rdOnce sync.Once
	closeRd := func() { rdOnce.Do(func() { rd.Close() }) }
	defer closeRd()

	log.Info("sensor ring buffer open — streaming syscall+TLS events to Redis",
		zap.String("stream", s.cfg.RedisStream),
	)

	go func() {
		<-ctx.Done()
		closeRd()
	}()

	var processedCount atomic.Int64

	for {
		record, err := rd.Read()
		if err != nil {
			if ctx.Err() != nil {
				return // clean shutdown
			}
			log.Warn("sensor ring buffer read error", zap.Error(err))
			continue
		}

		evt, err := parseSensorEvent(record.RawSample)
		if err != nil {
			log.Warn("failed to parse sensor event", zap.Error(err))
			continue
		}

		if evt.Path != "" {
			s.drift.Observe(evt.Path)
		}

		if err := s.publishSensorEvent(ctx, evt); err != nil {
			log.Error("failed to publish sensor event to Redis", zap.Error(err))
		}

		n := processedCount.Add(1)
		if n%1000 == 0 {
			log.Info("sensor2 event throughput checkpoint", zap.Int64("total_events", n))
		}
	}
}
