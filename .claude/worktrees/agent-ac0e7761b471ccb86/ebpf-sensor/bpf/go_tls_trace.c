// bpf/go_tls_trace.c — AuralisAPI Go TLS Sensor
//
// Hooks (3 programs):
//   1. uprobe/gotls_write       — Go crypto/tls.(*Conn).Write entry
//   2. uprobe/gotls_read_enter  — Go crypto/tls.(*Conn).Read entry (stash buf ptr)
//   3. uretprobe/gotls_read_exit — Go crypto/tls.(*Conn).Read exit (read decrypted data)
//
// Why these hooks?
//   OpenSSL uprobes in sensor.c cover libssl-linked C/Python/Ruby processes.
//   Go's standard library uses its own pure-Go crypto/tls implementation and
//   does NOT call libssl — so SSL_write/SSL_read uprobes are blind to Go HTTPS.
//   These uprobes instrument the Go runtime's TLS layer directly, completing
//   the coverage gap for Go-based microservices (e.g., api-gateway, other sensors).
//
// Go 1.17+ Register ABI (amd64):
//   Go switched from stack-based to register-based argument passing in 1.17.
//   For method uprobes on (*Conn).Write(b []byte):
//     AX = receiver (*Conn pointer)
//     BX = slice data pointer  (buf)
//     CX = slice length        (buf_len)
//     DI = slice capacity      (ignored)
//   GO_ARG_* macros from common.h access these registers.
//
// Maps:
//   events        (BPF_MAP_TYPE_RINGBUF) — 256 KB, same name as sensor.c but own object
//   go_read_args  (BPF_MAP_TYPE_HASH)    — buf ptr stash between Read entry/exit
//
// ── Memory Safety Contract ─────────────────────────────────────────────────────
//   1. buf_ptr==0 or buf_len==0 guard before every bpf_probe_read_user call.
//   2. go_read_args entries deleted unconditionally before conditional returns.
//   3. All ring buffer reserved slots either submitted or discarded.
//   4. Read lengths clamped to MAX_BUF_LEN (256) in emit_* helpers.
//
// Kernel compatibility: Linux >= 5.8 (BPF_MAP_TYPE_RINGBUF)
// Target arch: x86-64 (-D__TARGET_ARCH_x86, -target amd64)
// Compiler: clang with BPF target; bound to bpf2go via //go:generate in live.go

//go:build ignore
// +build ignore

#include "common.h"

// ── Maps ──────────────────────────────────────────────────────────────────────

// Primary event output stream — owns its own ring buffer instance separate
// from sensor.c so that the Go userspace can manage two independent readers.
struct {
    __uint(type,        BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB
} events SEC(".maps");

// Stashes the Read output buffer pointer between uprobe entry and uretprobe exit.
// Go's (*Conn).Read(b []byte) fills b with decrypted data before returning.
// The buffer address is passed in BX at entry but is only readable after return.
// Key: pid_tgid (unique per goroutine-to-thread mapping).
// Entry deleted unconditionally on exit to prevent stale map entries.
struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key,   __u64); // pid_tgid = (pid << 32) | tid
    __type(value, __u64); // userspace pointer to decrypted read buffer
} go_read_args SEC(".maps");

// ── Emit Helpers ──────────────────────────────────────────────────────────────
//
// Duplicated from sensor.c because each BPF object file has its own `events`
// map; emit_* functions must reference the local map symbol.

// emit_request_event: parses HTTP method + path from a Go TLS write buffer
// and submits a sensor_event_t to the ring buffer.
//
// Stack breakdown:
//   char method_buf[8]      =  8 bytes
//   char payload[256]       = 256 bytes
//   local scalars           ~ 32 bytes
//   total                   = 296 bytes  (< 512-byte BPF stack limit)
static __always_inline int emit_request_event(__u32 pid, __u32 tid,
                                               const void *buf, __u32 len,
                                               __u8 source, __u8 direction) {
    __u32 read_len = len < MAX_BUF_LEN ? len : MAX_BUF_LEN;

    char method_buf[MAX_METHOD_LEN] = {};
    if (parse_http_method(buf, read_len, method_buf) < 0)
        return -1;

    struct sensor_event_t *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return -1;

    evt->pid          = pid;
    evt->tid          = tid;
    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->status_code  = 0;
    evt->source       = source;
    evt->direction    = direction;
    __builtin_memcpy(evt->method, method_buf, MAX_METHOD_LEN);

    char payload[MAX_BUF_LEN] = {};
    if (bpf_probe_read_user(payload, read_len, buf) < 0) {
        bpf_ringbuf_discard(evt, 0);
        return -1;
    }

    extract_path(payload, read_len, evt->path);
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

// emit_response_event: parses HTTP status from a Go TLS read buffer
// and submits a sensor_event_t to the ring buffer.
//
// Stack breakdown:
//   char payload[256] = 256 bytes
//   local scalars     ~  32 bytes
//   total             = 288 bytes  (< 512-byte BPF stack limit)
static __always_inline int emit_response_event(__u32 pid, __u32 tid,
                                                const void *buf, __u32 len,
                                                __u8 source) {
    __u32 read_len = len < MAX_BUF_LEN ? len : MAX_BUF_LEN;

    char payload[MAX_BUF_LEN] = {};
    if (bpf_probe_read_user(payload, read_len, buf) < 0)
        return -1;

    __u16 status = parse_http_status(payload, read_len);
    if (!status)
        return -1;

    struct sensor_event_t *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return -1;

    __builtin_memset(evt, 0, sizeof(*evt));
    evt->pid          = pid;
    evt->tid          = tid;
    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->status_code  = status;
    evt->source       = source;
    evt->direction    = DIR_INGRESS;
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

// ── Program 1: uprobe/gotls_write ─────────────────────────────────────────────
// Fires at the entry of crypto/tls.(*Conn).Write(b []byte).
// The plaintext slice is already in registers before Go encrypts it.
//
// Go 1.17+ register ABI (amd64):
//   AX = receiver *tls.Conn  (implicit, ignored)
//   BX = b.data (slice pointer — buf_ptr)
//   CX = b.len  (slice length — buf_len)
//   DI = b.cap  (ignored)
//
// We emit a request event using the plaintext data before the TLS layer
// processes it. The HTTP method/path are visible at this point.
SEC("uprobe/gotls_write")
int uprobe_gotls_write(struct pt_regs *ctx)
{
    __u64 buf_ptr = GO_ARG_BX(ctx);
    __u64 buf_len = GO_ARG_CX(ctx);

    // Guard: zero pointer or zero-length write — nothing to capture.
    if (!buf_ptr || !buf_len)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;

    emit_request_event(pid, tid, (void *)buf_ptr, (__u32)buf_len,
                       SOURCE_GO_TLS, DIR_EGRESS);
    return 0;
}

// ── Program 2: uprobe/gotls_read_enter ────────────────────────────────────────
// Fires at the entry of crypto/tls.(*Conn).Read(b []byte).
// The receive buffer b is caller-allocated but EMPTY at entry — the TLS stack
// fills it with decrypted application data before returning.
// We save the data pointer so Program 3 can read the filled buffer.
//
// Go 1.17+ register ABI (amd64):
//   AX = receiver *tls.Conn  (implicit, ignored)
//   BX = b.data (slice pointer — buf_ptr to stash)
//   CX = b.len
//   DI = b.cap
SEC("uprobe/gotls_read_enter")
int uprobe_gotls_read_enter(struct pt_regs *ctx)
{
    __u64 buf_ptr = GO_ARG_BX(ctx);

    // Guard: null buf pointer — nothing to stash.
    if (!buf_ptr)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();

    // BPF_ANY: overwrite any stale entry from a prior Read call whose
    // uretprobe did not fire (e.g., goroutine preempted or killed).
    bpf_map_update_elem(&go_read_args, &pid_tgid, &buf_ptr, BPF_ANY);
    return 0;
}

// ── Program 3: uretprobe/gotls_read_exit ──────────────────────────────────────
// Fires when crypto/tls.(*Conn).Read(b []byte) returns.
// At this point Go has written n bytes of decrypted plaintext into b.
// The return value in AX (PT_REGS_RC) is n (bytes written), or 0 / negative on
// error/EOF.
//
// Key invariant: go_read_args entry is deleted unconditionally before any
// conditional return to prevent map exhaustion if the goroutine is killed
// between entry and exit.
SEC("uretprobe/gotls_read_exit")
int uprobe_gotls_read_exit(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid      = pid_tgid >> 32;
    __u32 tid      = (__u32)pid_tgid;

    // Retrieve the buf pointer saved by uprobe_gotls_read_enter.
    __u64 *buf_ptr_p = bpf_map_lookup_elem(&go_read_args, &pid_tgid);
    if (!buf_ptr_p)
        return 0;

    __u64 buf_ptr = *buf_ptr_p;

    // Delete unconditionally — primary defence against map entry leaks.
    // Must happen before the conditional return below.
    bpf_map_delete_elem(&go_read_args, &pid_tgid);

    // PT_REGS_RC extracts rax (return value n) on x86-64.
    // Go returns (n int, err error) but only n is in rax; err is in rbx.
    // We only care about n > 0 (bytes of decrypted data available).
    long ret = PT_REGS_RC(ctx);
    if (ret <= 0 || !buf_ptr)
        return 0;

    emit_response_event(pid, tid, (void *)buf_ptr, (__u32)ret, SOURCE_GO_TLS);
    return 0;
}

char _license[] SEC("license") = "GPL";
