//go:build !linux

// live_stub.go — Non-Linux stub for the live eBPF sensor.
//
// On Windows and macOS the bpf2go-generated types (HttpTraceObjects,
// SensorObjects, GoTlsObjects) do not exist because go generate requires
// clang on a Linux host. This stub satisfies the newLiveSensor call in
// sensor.go so the package compiles cleanly everywhere.
//
// SENSOR_MODE=live will return a clear error on non-Linux hosts at runtime.
// SENSOR_MODE=mock (the default) is unaffected.
package sensor

import (
	"fmt"

	"go.uber.org/zap"
)

func newLiveSensor(cfg Config, _ *zap.Logger) (Sensor, error) {
	return nil, fmt.Errorf(
		"live eBPF sensor requires Linux kernel >= 5.8 — current build target is not linux; use SENSOR_MODE=mock",
	)
}
