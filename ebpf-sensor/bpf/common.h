// bpf/common.h — AuralisAPI Shared BPF Header
//
// Centralises all includes, constants, the sensor_event_t struct, tracepoint
// argument accessors, HTTP parsing helpers, and Go ABI register macros so that
// sensor.c and go_tls_trace.c can share them without duplication.
//
// Usage: #include "common.h" at the top of each BPF source file.
//        Do NOT include in http_trace.c (that file defines its own http_event_t
//        with a different layout and has no dependency on sensor_event_t).
//
// Kernel compatibility: Linux >= 5.8 (BPF_MAP_TYPE_RINGBUF)
// Target arch: x86-64 (-D__TARGET_ARCH_x86, -target amd64)
#pragma once

// Pull in x86-64 struct pt_regs before BPF tracing headers so that
// PT_REGS_PARM / PT_REGS_RC macros have the full struct definition available.
#include <asm/ptrace.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// ── Constants ─────────────────────────────────────────────────────────────────

// Path and method buffer sizes — must match Go-side sensorEventC struct fields.
#define MAX_PATH_LEN    128
#define MAX_METHOD_LEN  8

// MAX_BUF_LEN controls the size of the on-stack read buffer in every program.
// 256 bytes leaves ~216 bytes of headroom for other locals within the 512-byte
// BPF stack limit per program (struct + locals ~296 bytes worst case).
#define MAX_BUF_LEN     256

// source — which probe captured the event (stored in sensor_event_t.source)
#define SOURCE_PLAIN    0   // syscall-level sendto/recvfrom: unencrypted traffic
#define SOURCE_TLS      1   // OpenSSL uprobe: plaintext captured around SSL layer
#define SOURCE_GO_TLS   2   // Go crypto/tls uprobe: plaintext from Go TLS stack

// direction — traffic flow relative to the monitored process
#define DIR_EGRESS      0   // outgoing: send / SSL_write / Write
#define DIR_INGRESS     1   // incoming: recv / SSL_read / Read

// ── Go 1.17+ Register-Based Calling Convention (amd64) ───────────────────────
//
// Go 1.17 switched from stack-based to register-based argument passing on
// amd64. The argument registers in order are: AX, BX, CX, DI (NOT the SysV
// DI, SI, DX, CX order used by C functions).
//
// When attaching a uprobe to a Go function, ctx->ax holds arg0, ctx->bx
// holds arg1, ctx->cx holds arg2, ctx->di holds arg3.
//
// Note on receiver: for method uprobes (e.g. crypto/tls.(*Conn).Write), the
// implicit receiver (*Conn) is arg0 in AX; the slice data pointer (buf) is
// arg1 in BX, slice length is arg2 in CX.
//
// References:
//   https://go.dev/s/regabi
//   https://cs.opensource.google/go/go/+/main:src/internal/abi/abi_amd64.s
// With -D__TARGET_ARCH_x86, bpf_tracing.h redefines struct pt_regs using
// r-prefixed field names (rax, rbx, rcx, rdi). Use PT_REGS_* macros via
// a typed cast so field access goes through the correct alias.
#define GO_ARG_AX(ctx) ((__u64)PT_REGS_RC((const struct pt_regs *)(ctx)))
#define GO_ARG_BX(ctx) ((__u64)(unsigned long)((const struct pt_regs *)(ctx))->rbx)
#define GO_ARG_CX(ctx) ((__u64)PT_REGS_PARM4((const struct pt_regs *)(ctx)))
#define GO_ARG_DI(ctx) ((__u64)PT_REGS_PARM1((const struct pt_regs *)(ctx)))

// ── Syscall Tracepoint Argument Accessors ─────────────────────────────────────
//
// We do NOT use preserve_access_index shadow structs for tracepoint contexts
// because the generated struct name does not exist in the kernel's BTF type
// database — CO-RE relocation would fail at load time.
//
// Instead we read args at well-known, ABI-stable byte offsets:
//
//   offset  0: struct trace_entry { u16 type; u8 flags; u8 preempt_count; int pid; }
//              = 8 bytes total (ABI-stable since Linux 2.6.27)
//   offset  8: long id         (syscall number)
//   offset 16: unsigned long args[0]
//   offset 24: unsigned long args[1]
//   offset 32: unsigned long args[2]
//   ...
//
// sys_exit_* layout:
//   offset  0: struct trace_entry  (8 bytes)
//   offset  8: long id
//   offset 16: long ret            ← return value (bytes received, or -errno)

// tp_read_arg: reads syscall argument n (0-based) from a sys_enter_* context.
static __always_inline unsigned long tp_read_arg(void *ctx, __u32 n) {
    unsigned long val = 0;
    bpf_probe_read_kernel(&val, sizeof(val),
                          (unsigned char *)ctx + 16 + n * sizeof(unsigned long));
    return val;
}

// tp_read_ret: reads the return value from a sys_exit_* tracepoint context.
static __always_inline long tp_read_ret(void *ctx) {
    long val = 0;
    bpf_probe_read_kernel(&val, sizeof(val), (unsigned char *)ctx + 16);
    return val;
}

// ── Event Structure ────────────────────────────────────────────────────────────
//
// Published to the ring buffer; parsed by Go using encoding/binary.LittleEndian.
// WARNING: Go's sensorEventC struct in live.go MUST match this layout exactly.
//          Do NOT reorder fields. All padding is explicit.
//
// x86-64 little-endian layout (clang default packing):
//   __u32  pid;           offset  0,  4 bytes
//   __u32  tid;           offset  4,  4 bytes
//   __u64  timestamp_ns;  offset  8,  8 bytes
//   __u16  status_code;   offset 16,  2 bytes
//   __u8   source;        offset 18,  1 byte  (SOURCE_PLAIN | SOURCE_TLS | SOURCE_GO_TLS)
//   __u8   direction;     offset 19,  1 byte  (DIR_EGRESS | DIR_INGRESS)
//   char   method[8];     offset 20,  8 bytes
//   char   path[128];     offset 28, 128 bytes
//   __u8   _pad[4];       offset 156, 4 bytes → sizeof = 160
struct sensor_event_t {
    __u32  pid;
    __u32  tid;
    __u64  timestamp_ns;
    __u16  status_code;
    __u8   source;
    __u8   direction;
    char   method[MAX_METHOD_LEN];
    char   path[MAX_PATH_LEN];
    __u8   _pad[4];
};

// ── HTTP Parsing Helpers ──────────────────────────────────────────────────────
//
// These are shared by sensor.c and go_tls_trace.c. They operate on a
// caller-supplied stack buffer (already read by bpf_probe_read_user) so they
// themselves do not perform any user-memory accesses.

// parse_http_method: identifies the HTTP request method in the first bytes of
// a user-space buffer. Reads up to MAX_METHOD_LEN-1 bytes via bpf_probe_read_user.
// Returns 0 on success and writes the null-terminated method string to *out.
// Returns -1 if buf does not begin with a recognised HTTP method (non-HTTP dropped).
//
// Safety: read bounded to MAX_METHOD_LEN-1 = 7 bytes; *out zero-initialised by
// caller so null termination is guaranteed even if memcpy writes no terminator.
static __always_inline int parse_http_method(const void *buf, __u32 len,
                                              char *out) {
    if (len < 4)
        return -1;

    char tmp[MAX_METHOD_LEN] = {};
    if (bpf_probe_read_user(tmp, MAX_METHOD_LEN - 1, buf) < 0)
        return -1;

    if (tmp[0]=='G' && tmp[1]=='E' && tmp[2]=='T' && tmp[3]==' ')
        { __builtin_memcpy(out, "GET\0",    4); return 0; }
    if (tmp[0]=='P' && tmp[1]=='O' && tmp[2]=='S' && tmp[3]=='T')
        { __builtin_memcpy(out, "POST\0",   5); return 0; }
    if (tmp[0]=='P' && tmp[1]=='U' && tmp[2]=='T' && tmp[3]==' ')
        { __builtin_memcpy(out, "PUT\0",    4); return 0; }
    if (tmp[0]=='D' && tmp[1]=='E' && tmp[2]=='L' && tmp[3]=='E')
        { __builtin_memcpy(out, "DELETE\0", 7); return 0; }
    if (tmp[0]=='P' && tmp[1]=='A' && tmp[2]=='T' && tmp[3]=='C')
        { __builtin_memcpy(out, "PATCH\0",  6); return 0; }
    if (tmp[0]=='H' && tmp[1]=='E' && tmp[2]=='A' && tmp[3]=='D')
        { __builtin_memcpy(out, "HEAD\0",   5); return 0; }
    return -1;
}

// extract_path: scans a payload buffer for the URL path token following the
// HTTP method token (e.g. "GET /api/v1/users HTTP/1.1" → "/api/v1/users").
// Writes at most MAX_PATH_LEN-1 bytes to *out (caller zero-initialises it).
//
// All array accesses are bounded by read_len and MAX_PATH_LEN — the BPF
// verifier can statically prove these bounds are satisfied.
static __always_inline void extract_path(const char *buf, __u32 read_len,
                                          char *out) {
    int path_start = -1;
    #pragma unroll
    for (int i = 0; i < MAX_METHOD_LEN + 1; i++) {
        if (buf[i] == ' ') { path_start = i + 1; break; }
    }
    if (path_start < 0 || path_start >= MAX_BUF_LEN)
        return;

    #pragma unroll
    for (int i = 0; i < MAX_PATH_LEN - 1; i++) {
        int idx = path_start + i;
        // MAX_PATH_LEN (128) <= MAX_BUF_LEN (256) — verifier can prove idx < MAX_BUF_LEN.
        if (idx >= MAX_BUF_LEN) break;
        char c = buf[idx];
        if (c == ' ' || c == '\r' || c == '\n' || c == '\0') break;
        out[i] = c;
    }
}

// parse_http_status: extracts the 3-digit HTTP status code from a response
// first-line of the form "HTTP/1.1 200 OK\r\n" or "HTTP/2 404 Not Found\r\n".
// Returns 0 if buf does not start with a valid HTTP response line.
// Stack cost: purely register-based; no additional local arrays.
static __always_inline __u16 parse_http_status(const char *buf, __u32 len) {
    if (len < 12)
        return 0;
    if (buf[0]!='H' || buf[1]!='T' || buf[2]!='T' || buf[3]!='P' || buf[4]!='/')
        return 0;

    // Find the first space separating the HTTP version token from the status code.
    int sp = -1;
    #pragma unroll
    for (int i = 5; i < 12 && i < (int)len; i++) {
        if (buf[i] == ' ') { sp = i + 1; break; }
    }
    if (sp < 0 || sp + 2 >= (int)len)
        return 0;

    char d0 = buf[sp], d1 = buf[sp+1], d2 = buf[sp+2];
    if (d0 < '1' || d0 > '5') return 0;
    if (d1 < '0' || d1 > '9') return 0;
    if (d2 < '0' || d2 > '9') return 0;
    return (__u16)((d0 - '0') * 100 + (d1 - '0') * 10 + (d2 - '0'));
}
