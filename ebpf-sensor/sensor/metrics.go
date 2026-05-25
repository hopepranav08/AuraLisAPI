// sensor/metrics.go — lightweight Prometheus-compatible metrics for the eBPF sensor.
//
// Uses sync/atomic for lock-free counter updates so hot paths (event replay,
// drift alarm callbacks) can increment without blocking.
//
// Exposed via GET /metrics in main.go in Prometheus text format 0.0.4.
package sensor

import (
	"fmt"
	"sync/atomic"
)

var (
	// MetricEventsPublished counts every event successfully written to the Redis stream.
	MetricEventsPublished atomic.Uint64

	// MetricDriftAlarmsTotal counts every DriftAlert published (any alarm_type).
	MetricDriftAlarmsTotal atomic.Uint64
)

// PrometheusMetrics returns a Prometheus text-format 0.0.4 payload with the
// current counter values. Called from the /metrics HTTP handler in main.go.
func PrometheusMetrics() string {
	evts  := MetricEventsPublished.Load()
	alarms := MetricDriftAlarmsTotal.Load()

	return fmt.Sprintf(
		"# HELP auralis_events_published_total Total HTTP events published to the Redis stream.\n"+
			"# TYPE auralis_events_published_total counter\n"+
			"auralis_events_published_total %d\n"+
			"# HELP auralis_drift_alarms_total Total drift alarms (any alarm_type) fired by the sensor.\n"+
			"# TYPE auralis_drift_alarms_total counter\n"+
			"auralis_drift_alarms_total %d\n",
		evts, alarms,
	)
}
