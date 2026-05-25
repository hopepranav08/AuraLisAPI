// sensor/sensor.go — Sensor abstraction layer.
// Routes to LiveSensor (eBPF) or MockSensor based on Config.Mode.
package sensor

import (
	"context"
	"fmt"

	"go.uber.org/zap"
)

// Config holds runtime configuration for the sensor.
type Config struct {
	Mode        string // "live" | "mock"
	RedisAddr   string
	RedisStream string
	FixturesDir string
}

// Sensor is the interface both modes implement.
type Sensor interface {
	// Run starts the sensor and blocks until ctx is cancelled or a fatal error
	// occurs. Returns nil on clean shutdown.
	Run(ctx context.Context) error

	// DriftStats returns a point-in-time snapshot of per-endpoint PH drift
	// state for all observed endpoints. Used by the /drift/stats HTTP handler.
	DriftStats() []EndpointStats
}

// New returns the appropriate Sensor implementation based on cfg.Mode.
func New(cfg Config, log *zap.Logger) (Sensor, error) {
	switch cfg.Mode {
	case "live":
		return newLiveSensor(cfg, log)
	case "mock":
		return newMockSensor(cfg, log)
	default:
		return nil, fmt.Errorf("unknown SENSOR_MODE %q — must be 'live' or 'mock'", cfg.Mode)
	}
}
