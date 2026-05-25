// sensor/reporter.go — Remote brain HTTP reporter.
//
// When BRAIN_URL is configured (company install mode), the sensor registers
// itself with the hosted brain and forwards every captured event via HTTP POST.
// This runs alongside normal Redis publishing — local Redis is still used if
// REDIS_ADDR is also configured.
package sensor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"go.uber.org/zap"
)

// BrainReporter forwards events and drift alerts to a remote AuralisAPI brain.
type BrainReporter struct {
	brainURL  string
	token     string
	sensorID  string
	mode      string // "live" | "mock"
	client    *http.Client
	log       *zap.Logger
	mu        sync.Mutex
	connected bool
}

// NewBrainReporter creates a reporter. If brainURL is empty, Report() is a no-op.
func NewBrainReporter(cfg Config, log *zap.Logger) *BrainReporter {
	sensorID := cfg.SensorID
	if sensorID == "" {
		if h, err := os.Hostname(); err == nil {
			sensorID = "sensor-" + h
		} else {
			sensorID = fmt.Sprintf("sensor-%d", time.Now().UnixNano()%100000)
		}
	}
	mode := cfg.Mode
	if mode == "" {
		mode = "mock"
	}
	return &BrainReporter{
		brainURL: cfg.BrainURL,
		token:    cfg.CompanyToken,
		sensorID: sensorID,
		mode:     mode,
		client:   &http.Client{Timeout: 5 * time.Second},
		log:      log,
	}
}

// Register announces this sensor to the brain. Call once at startup.
func (r *BrainReporter) Register(ctx context.Context) {
	if r.brainURL == "" {
		return
	}

	hostname, _ := os.Hostname()
	body, _ := json.Marshal(map[string]string{
		"sensor_id": r.sensorID,
		"hostname":  hostname,
		"mode":      r.mode,
		"version":   "1.0.0",
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		r.brainURL+"/sensor/register", bytes.NewReader(body))
	if err != nil {
		r.log.Warn("brain register: request build failed", zap.Error(err))
		return
	}
	r.setHeaders(req)

	resp, err := r.client.Do(req)
	if err != nil {
		r.log.Warn("brain register: connection failed", zap.Error(err),
			zap.String("brain_url", r.brainURL))
		return
	}
	defer resp.Body.Close()

	r.mu.Lock()
	r.connected = resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated
	r.mu.Unlock()

	r.log.Info("sensor registered with brain",
		zap.String("sensor_id", r.sensorID),
		zap.String("brain_url", r.brainURL),
		zap.Int("status", resp.StatusCode),
	)
}

// Report forwards a single event payload (already JSON) to the brain.
// Fire-and-forget: errors are logged but never returned.
func (r *BrainReporter) Report(ctx context.Context, payload []byte) {
	if r.brainURL == "" {
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		r.brainURL+"/sensor/ingest", bytes.NewReader(payload))
	if err != nil {
		r.log.Warn("brain ingest: request build failed", zap.Error(err))
		return
	}
	r.setHeaders(req)

	resp, err := r.client.Do(req)
	if err != nil {
		r.log.Warn("brain ingest: send failed", zap.Error(err))
		return
	}
	defer resp.Body.Close()
}

// ReportAlert forwards a drift alert to the brain.
func (r *BrainReporter) ReportAlert(ctx context.Context, alert DriftAlert) {
	if r.brainURL == "" {
		return
	}
	payload, err := json.Marshal(alert)
	if err != nil {
		return
	}
	r.Report(ctx, payload)
}

// Connected returns whether the last registration succeeded.
func (r *BrainReporter) Connected() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.connected
}

// SensorID returns the sensor's unique ID string.
func (r *BrainReporter) SensorID() string { return r.sensorID }

func (r *BrainReporter) setHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sensor-ID", r.sensorID)
	if r.token != "" {
		req.Header.Set("Authorization", "Bearer "+r.token)
	}
}
