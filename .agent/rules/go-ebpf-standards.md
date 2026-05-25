---
trigger: always_on
---

When generating Go code interacting with eBPF:

Use the cilium/ebpf library.

Always load programs using bpf2go.

Do not strip debug symbols from Go binaries.

Use ring buffer maps (BPF_MAP_TYPE_RINGBUF) for streaming events.

Ensure all bpf_probe_read_user calls validate memory boundaries.

Support Go 1.17+ register calling conventions.

Avoid unsafe pointer arithmetic.

Kernel safety is mandatory.