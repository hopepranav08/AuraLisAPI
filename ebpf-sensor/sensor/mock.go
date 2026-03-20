// sensor/mock.go — Mock sensor for local development on non-Linux hosts.
//
// Reads events from fixtures/events.jsonl and replays them to Redis in a loop
// with configurable inter-event delay, simulating a live eBPF sensor.
//
// Additional behaviour:
//   - Feeds each replayed event into the DriftEngine for change-point detection.
//   - After 5 full replay loops, injects a "zombie burst": 20 rapid requests to
//     deprecated legacy-payments endpoints (simulating attacker reconnaissance
//     after an API goes dormant). This should trigger a DriftAlert with
//     alarm_type "resurrection" or "resurrection+ph_threshold".
//   - Publishes DriftAlerts to the same Redis stream so remediation-brain can
//     consume them in mock/demo mode.
package sensor

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

type mockSensor struct {
	cfg       Config
	log       *zap.Logger
	rdb       *redis.Client
	drift     *DriftEngine
	loopCount int // tracks how many full replay cycles have completed
}

func newMockSensor(cfg Config, log *zap.Logger) (*mockSensor, error) {
	rdb := redis.NewClient(&redis.Options{Addr: cfg.RedisAddr})
	drift := NewDriftEngine(DefaultDriftConfig(), log.Named("drift"))
	return &mockSensor{cfg: cfg, log: log, rdb: rdb, drift: drift}, nil
}

func (s *mockSensor) Run(ctx context.Context) error {
	s.log.Info("Mock sensor starting — replaying fixtures",
		zap.String("fixtures_dir", s.cfg.FixturesDir),
		zap.String("stream", s.cfg.RedisStream),
	)

	// Start the drift detection engine. It runs until ctx is cancelled,
	// calling publishDriftAlert whenever the PH detector fires.
	go s.drift.Run(ctx, s.publishDriftAlert)

	fixturePath := filepath.Join(s.cfg.FixturesDir, "events.jsonl")
	zombieBurstFired := false

	for {
		if err := s.replayFile(ctx, fixturePath); err != nil {
			return err
		}
		s.loopCount++

		// After 5 complete replay loops, inject the zombie burst exactly once.
		// This simulates an attacker probing a dormant API endpoint after
		// observing zero traffic to it for several drift windows.
		if s.loopCount >= 5 && !zombieBurstFired {
			zombieBurstFired = true
			s.log.Info("zombie burst trigger: injecting reconnaissance traffic",
				zap.Int("loop_count", s.loopCount),
			)
			if err := s.injectZombieBurst(ctx); err != nil {
				s.log.Error("zombie burst injection failed", zap.Error(err))
			}
		}

		// Wait before starting the next cycle.
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(5 * time.Second):
		}
	}
}

// replayFile reads events.jsonl line by line, injects current timestamps,
// publishes each to Redis, and observes each path in the drift engine.
func (s *mockSensor) replayFile(ctx context.Context, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("cannot open fixture file %s: %w", path, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		line := scanner.Text()
		if line == "" {
			continue
		}

		// Validate JSON and extract fields.
		var raw map[string]interface{}
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			s.log.Warn("skipping malformed fixture line", zap.String("line", line))
			continue
		}

		// Inject current timestamp before publishing.
		raw["timestamp_ns"] = time.Now().UnixNano()
		payload, _ := json.Marshal(raw)

		if err := s.rdb.XAdd(ctx, &redis.XAddArgs{
			Stream: s.cfg.RedisStream,
			Values: map[string]interface{}{"data": string(payload)},
		}).Err(); err != nil {
			s.log.Error("redis publish failed", zap.Error(err))
			continue
		}

		// Extract path for drift observation.
		if pathVal, ok := raw["path"].(string); ok && pathVal != "" {
			s.drift.Observe(pathVal)
		}

		s.log.Debug("published mock event", zap.String("path", fmt.Sprintf("%v", raw["path"])))

		// Simulate ~100ms inter-event delay.
		time.Sleep(100 * time.Millisecond)
	}

	return scanner.Err()
}

// injectZombieBurst simulates attacker reconnaissance against a dormant legacy
// API endpoint. Sends 20 rapid requests to /api/v1/legacy-payments and its
// sub-paths using randomised methods (GET/POST) and slight path variations.
//
// The inter-event delay is 50ms (faster than normal replay) to simulate a
// scanner or automated tool. Each request is observed in the drift engine,
// which should fire a "resurrection" alarm after the first non-zero window
// following multiple zero-count windows.
func (s *mockSensor) injectZombieBurst(ctx context.Context) error {
	// Realistic path variations simulating an attacker enumerating endpoints.
	paths := []string{
		"/api/v1/legacy-payments",
		"/api/v1/legacy-payments/charge",
		"/api/v1/legacy-payments/refund",
		"/api/v1/legacy-payments",
		"/api/v1/legacy-payments/charge",
		"/api/v1/legacy-payments",
	}
	methods := []string{"GET", "POST"}

	s.log.Info("injecting zombie burst", zap.Int("events", 20))

	for i := 0; i < 20; i++ {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		// Randomise method and path for realistic variation.
		method := methods[rand.Intn(len(methods))]
		path := paths[rand.Intn(len(paths))]

		evt := map[string]interface{}{
			"method":       method,
			"path":         path,
			"status_code":  200,
			"pid":          9999,
			"source":       "plain",
			"direction":    "egress",
			"timestamp_ns": time.Now().UnixNano(),
		}
		payload, _ := json.Marshal(evt)

		if err := s.rdb.XAdd(ctx, &redis.XAddArgs{
			Stream: s.cfg.RedisStream,
			Values: map[string]interface{}{"data": string(payload)},
		}).Err(); err != nil {
			s.log.Error("zombie burst redis publish failed", zap.Error(err))
		}

		// Observe each path for drift detection. The burst of traffic to a
		// previously-zero endpoint should trigger a resurrection alarm.
		s.drift.Observe(path)

		s.log.Debug("zombie burst event",
			zap.Int("i", i+1),
			zap.String("method", method),
			zap.String("path", path),
		)

		// 50ms inter-event delay — faster than normal replay, mimics scanner.
		time.Sleep(50 * time.Millisecond)
	}

	return nil
}

// publishDriftAlert marshals a DriftAlert and writes it to the Redis stream.
// The remediation-brain consumes drift_alert events to trigger LangGraph workflows.
func (s *mockSensor) publishDriftAlert(ctx context.Context, alert DriftAlert) error {
	payload, err := json.Marshal(alert)
	if err != nil {
		return fmt.Errorf("json marshal drift alert: %w", err)
	}

	s.log.Info("drift alert fired",
		zap.String("endpoint", alert.Endpoint),
		zap.String("alarm_type", alert.AlarmType),
		zap.Float64("count", alert.WindowCount),
		zap.Float64("ph_score", alert.PHScore),
	)

	return s.rdb.XAdd(ctx, &redis.XAddArgs{
		Stream: s.cfg.RedisStream,
		Values: map[string]interface{}{"data": string(payload)},
	}).Err()
}

// DriftStats returns a snapshot of all endpoint drift states.
// Called from the /drift/stats HTTP handler in main.go.
func (s *mockSensor) DriftStats() []EndpointStats {
	return s.drift.Stats()
}
