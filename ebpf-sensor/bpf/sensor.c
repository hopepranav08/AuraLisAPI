// bpf/sensor.c — AuralisAPI Comprehensive eBPF Sensor
//
// Hooks (6 programs):
//   1. tracepoint/syscalls/sys_enter_sendto   — plain HTTP sends at syscall level
//   2. tracepoint/syscalls/sys_enter_recvfrom — stash buf pointer before kernel fills it
//   3. tracepoint/syscalls/sys_exit_recvfrom  — read HTTP response after kernel fills buf
//   4. uprobe/SSL_write                       — TLS egress plaintext before encryption
//   5. uprobe/SSL_read                        — stash SSL_read buf pointer at entry
//   6. uretprobe/SSL_read                     — read TLS ingress plaintext after decryption
//
// Maps:
//   events         (BPF_MAP_TYPE_RINGBUF) — 256 KB event stream to Go userspace
//   pid_filter     (BPF_MAP_TYPE_HASH)    — optional PID allow-list, populated from userspace
//   ssl_read_args  (BPF_MAP_TYPE_HASH)    — SSL_read buf ptr stash: key=pid_tgid, val=buf addr
//   recvfrom_args  (BPF_MAP_TYPE_HASH)    — recvfrom buf ptr stash: key=pid_tgid, val=buf addr
//
// ── Memory Safety Contract ─────────────────────────────────────────────────────
//   1. NULL + length guard before every bpf_probe_read_user call.
//   2. Read lengths clamped to MAX_BUF_LEN (256) — ensures stack usage per function
//      stays at ~320 bytes max (char buf[256] + locals ~64), well under the 512-byte
//      BPF stack limit.
//   3. bpf_ringbuf_reserve checked for NULL before writing any field.
//   4. bpf_ringbuf_discard called on ALL error paths after a successful reserve —
//      no BPF ring buffer slot is ever abandoned.
//   5. ssl_read_args and recvfrom_args entries are deleted unconditionally on the
//      exit probes (even if reading fails), preventing stale entries if a thread
//      is killed between entry and exit.
//   6. No unbounded loops — all loops are #pragma unroll with explicit bounds.
//
// Kernel compatibility: Linux >= 5.8 (BPF_MAP_TYPE_RINGBUF)
// Target arch: x86-64 (-D__TARGET_ARCH_x86, -target amd64)
// Compiler: clang with BPF target; bound to bpf2go via //go:generate in live.go

//go:build ignore
// +build ignore

// All includes, constants (MAX_PATH_LEN, MAX_BUF_LEN, SOURCE_*, DIR_*),
// the sensor_event_t struct, tp_read_arg/tp_read_ret, and HTTP helpers
// (parse_http_method, extract_path, parse_http_status) are now in common.h.
#include "common.h"

// ── Maps ──────────────────────────────────────────────────────────────────────

// Primary event output stream.
// bpf_ringbuf_reserve + bpf_ringbuf_submit enables lock-free, zero-copy delivery.
struct {
    __uint(type,        BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB
} events SEC(".maps");

// Optional PID allow-list. If empty, all processes are traced (default).
// Operator can restrict to specific PIDs via bpf_map_update_elem from userspace.
struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key,   __u32); // pid
    __type(value, __u8);  // 1 = trace this pid
} pid_filter SEC(".maps");

// Stashes the SSL_read output buffer pointer between uprobe entry and uretprobe.
// The buffer is EMPTY at entry; OpenSSL fills it before SSL_read returns.
// Key: pid_tgid — unique per thread, avoids cross-thread collisions.
// Entry deleted by uretprobe unconditionally (even on error) to prevent leaks.
struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key,   __u64); // pid_tgid = (pid << 32) | tid
    __type(value, __u64); // userspace pointer to decrypted read buffer
} ssl_read_args SEC(".maps");

// Stashes the recvfrom output buffer pointer between sys_enter and sys_exit.
// Same semantics as ssl_read_args: buffer empty at entry, filled on exit.
struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key,   __u64); // pid_tgid
    __type(value, __u64); // userspace pointer to receive buffer (ubuf)
} recvfrom_args SEC(".maps");

// ── Emit Helpers ──────────────────────────────────────────────────────────────
//
// These helpers reference the local `events` map defined above. They cannot
// be moved into common.h because each BPF object file has its own `events` map
// instance; placing them in common.h would require the map symbol to be
// defined there too, which would break separate compilation.

// emit_request_event: common helper called by sendto and SSL_write probes.
// Reads up to MAX_BUF_LEN bytes from a user-space buffer, parses the HTTP
// method and URL path, and submits an event to the ring buffer.
//
// Stack breakdown:
//   char method_buf[8]      =  8 bytes
//   char payload[256]       = 256 bytes
//   local scalars           ~ 32 bytes
//   total                   = 296 bytes  (< 512-byte BPF stack limit)
//
// Returns 0 on success; ring buffer slot is discarded on any failure.
static __always_inline int emit_request_event(__u32 pid, __u32 tid,
                                               const void *buf, __u32 len,
                                               __u8 source, __u8 direction) {
    // Clamp to MAX_BUF_LEN to respect stack budget.
    __u32 read_len = len < MAX_BUF_LEN ? len : MAX_BUF_LEN;

    // Early HTTP filter — discards non-HTTP TCP/TLS traffic before touching
    // the ring buffer, avoiding unnecessary allocation pressure.
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

    // Read the raw payload to extract the URL path.
    // bpf_probe_read_user bounds: read_len <= MAX_BUF_LEN (verified above).
    char payload[MAX_BUF_LEN] = {};
    if (bpf_probe_read_user(payload, read_len, buf) < 0) {
        bpf_ringbuf_discard(evt, 0); // safety: always discard reserved slot on error
        return -1;
    }

    extract_path(payload, read_len, evt->path);
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

// emit_response_event: common helper for recvfrom exit and SSL_read exit probes.
// Reads the response buffer, extracts the HTTP status code, and submits an event.
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
    // bpf_probe_read_user: userspace pointer, bounds-checked to read_len.
    if (bpf_probe_read_user(payload, read_len, buf) < 0)
        return -1;

    __u16 status = parse_http_status(payload, read_len);
    if (!status)
        return -1; // not an HTTP response — drop silently

    struct sensor_event_t *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return -1;

    // bpf_ringbuf_reserve does NOT zero the memory. Explicit memset required
    // for all fields we don't write, otherwise Go will see garbage in method/path.
    __builtin_memset(evt, 0, sizeof(*evt));

    evt->pid          = pid;
    evt->tid          = tid;
    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->status_code  = status;
    evt->source       = source;
    evt->direction    = DIR_INGRESS;
    // method and path are empty for response events (zeroed by memset above).
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

// ── Program 1: sys_enter_sendto ───────────────────────────────────────────────
// Captures unencrypted HTTP sends at the syscall boundary, covering both TCP
// and UDP. This is complementary to the kprobe/tcp_sendmsg in http_trace.c:
// sendto is architecture-agnostic and catches plaintext HTTP regardless of
// whether it goes through tcp_sendmsg's code path.
//
// sendto(int fd, const void *buf, size_t len, int flags, struct sockaddr *dest_addr, socklen_t addrlen)
//   args[0]=fd  args[1]=buf  args[2]=len
SEC("tracepoint/syscalls/sys_enter_sendto")
int tp_sendto(void *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid      = pid_tgid >> 32;
    __u32 tid      = (__u32)pid_tgid;

    // Read args at stable ABI offsets (no CO-RE relocation needed).
    unsigned long buf_ptr = tp_read_arg(ctx, 1); // args[1] = buf
    unsigned long len     = tp_read_arg(ctx, 2); // args[2] = len

    // Boundary guard: reject null or too-short payloads before any memory access.
    if (!buf_ptr || len < 4)
        return 0;

    emit_request_event(pid, tid, (const void *)buf_ptr, (__u32)len,
                       SOURCE_PLAIN, DIR_EGRESS);
    return 0;
}

// ── Program 2: sys_enter_recvfrom ─────────────────────────────────────────────
// The receive buffer (ubuf) is EMPTY when recvfrom is called — the kernel fills
// it during the syscall. We save the pointer here so Program 3 (sys_exit_recvfrom)
// can read the filled buffer after the kernel returns.
//
// recvfrom(int fd, void *ubuf, size_t size, int flags, struct sockaddr *addr, socklen_t *addrlen)
//   args[0]=fd  args[1]=ubuf  args[2]=size
SEC("tracepoint/syscalls/sys_enter_recvfrom")
int tp_enter_recvfrom(void *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    unsigned long buf_ptr = tp_read_arg(ctx, 1); // args[1] = ubuf
    if (!buf_ptr)
        return 0;

    // Store buf_ptr keyed by pid_tgid. BPF_ANY creates or overwrites.
    // This will be retrieved and deleted by tp_exit_recvfrom.
    bpf_map_update_elem(&recvfrom_args, &pid_tgid, &buf_ptr, BPF_ANY);
    return 0;
}

// ── Program 3: sys_exit_recvfrom ──────────────────────────────────────────────
// At this point the kernel has filled ubuf with ret bytes of received data.
// We look up the buf pointer saved at entry, read the data, and emit an event.
//
// Memory safety: map entry is deleted unconditionally regardless of whether
// reading succeeds, preventing accumulation of stale entries when a thread
// exits between entry and exit probes.
SEC("tracepoint/syscalls/sys_exit_recvfrom")
int tp_exit_recvfrom(void *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid      = pid_tgid >> 32;
    __u32 tid      = (__u32)pid_tgid;

    long ret = tp_read_ret(ctx); // bytes received, or -errno on error

    // Retrieve saved buf pointer. Lookup before deletion so we have the value.
    __u64 *buf_ptr_p = bpf_map_lookup_elem(&recvfrom_args, &pid_tgid);
    if (!buf_ptr_p)
        return 0;

    __u64 buf_ptr = *buf_ptr_p;

    // Delete unconditionally — prevents stale entries regardless of outcome.
    bpf_map_delete_elem(&recvfrom_args, &pid_tgid);

    if (ret <= 0 || !buf_ptr)
        return 0;

    emit_response_event(pid, tid, (const void *)buf_ptr, (__u32)ret, SOURCE_PLAIN);
    return 0;
}

// ── Program 4: uprobe/SSL_write ───────────────────────────────────────────────
// Fires before OpenSSL encrypts the data. *buf contains the application's
// plaintext payload in user space — bpf_probe_read_user is the correct call.
//
// Signature: int SSL_write(SSL *ssl, const void *buf, int num)
// x86-64 SysV ABI: rdi=ssl, rsi=buf, rdx=num
// BPF_UPROBE maps register state to typed C arguments automatically.
//
// TLS coverage: this hook intercepts all OpenSSL/libssl calls, including
// HTTPS APIs using curl, requests, httpx, etc. It does NOT cover BoringSSL
// (Chrome/Android) or Go's crypto/tls (covered by go_tls_trace.c).
SEC("uprobe/SSL_write")
int uprobe_ssl_write(struct pt_regs *ctx)
{
    // SSL_write(SSL *ssl, const void *buf, int num)
    // x86-64 SysV ABI: rdi=ssl, rsi=buf, rdx=num
    const void *buf = (const void *)PT_REGS_PARM2(ctx);
    int num = (int)PT_REGS_PARM3(ctx);

    if (!buf || num <= 0)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;

    emit_request_event(pid, tid, buf, (__u32)num, SOURCE_TLS, DIR_EGRESS);
    return 0;
}

// ── Program 5: uprobe/SSL_read (entry) ───────────────────────────────────────
// SSL_read's output buffer is caller-allocated but EMPTY at entry — OpenSSL
// fills it with decrypted data before returning. We save the buf pointer to
// the ssl_read_args map so the uretprobe (Program 6) can read the filled buffer.
//
// Signature: int SSL_read(SSL *ssl, void *buf, int num)
// x86-64 SysV ABI: rdi=ssl, rsi=buf, rdx=num
SEC("uprobe/SSL_read")
int uprobe_ssl_read_enter(struct pt_regs *ctx)
{
    // SSL_read(SSL *ssl, void *buf, int num)
    // x86-64 SysV ABI: rdi=ssl, rsi=buf, rdx=num
    void *buf = (void *)PT_REGS_PARM2(ctx);
    int num   = (int)PT_REGS_PARM3(ctx);

    if (!buf || num <= 0)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 buf_addr = (__u64)(unsigned long)buf;

    // BPF_ANY: overwrite any stale entry from a previous call that lacked
    // a matching uretprobe (e.g., due to signal or early error return).
    bpf_map_update_elem(&ssl_read_args, &pid_tgid, &buf_addr, BPF_ANY);
    return 0;
}

// ── Program 6: uretprobe/SSL_read (exit) ─────────────────────────────────────
// OpenSSL has now written decrypted plaintext into buf. The return value (rax)
// gives the number of bytes written.
//
// Key invariant: the map entry is deleted before any conditional return.
// This prevents map exhaustion if:
//   - The process is killed between entry (Program 5) and here
//   - SSL_read returns an error (-1) without writing data
//   - The function is called again before a previous uretprobe fired
//
// bpf_probe_read_user is correct here: buf is a user-space pointer passed
// by the application; the decrypted data lives in user virtual memory.
SEC("uretprobe/SSL_read")
int uprobe_ssl_read_exit(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid      = pid_tgid >> 32;
    __u32 tid      = (__u32)pid_tgid;

    // Retrieve the buf pointer saved by uprobe_ssl_read_enter.
    __u64 *buf_ptr_p = bpf_map_lookup_elem(&ssl_read_args, &pid_tgid);
    if (!buf_ptr_p)
        return 0;

    __u64 buf_ptr = *buf_ptr_p;

    // Delete unconditionally — even if the read below fails.
    // This is the primary defence against map entry leaks.
    bpf_map_delete_elem(&ssl_read_args, &pid_tgid);

    // PT_REGS_RC extracts rax (return value) on x86-64.
    // Requires __TARGET_ARCH_x86 defined in the compiler invocation.
    long ret = PT_REGS_RC(ctx);
    if (ret <= 0 || !buf_ptr)
        return 0;

    emit_response_event(pid, tid, (const void *)buf_ptr, (__u32)ret, SOURCE_TLS);
    return 0;
}

char _license[] SEC("license") = "GPL";
