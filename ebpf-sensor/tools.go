//go:build tools

package main

// Tool dependencies — imported here so go mod tidy adds them to go.sum.
// bpf2go compiles bpf/http_trace.c into Go-embeddable eBPF objects during
// `go generate ./...` (invoked from sensor/live.go).
import _ "github.com/cilium/ebpf/cmd/bpf2go"
