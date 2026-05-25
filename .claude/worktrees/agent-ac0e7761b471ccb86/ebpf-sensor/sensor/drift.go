// sensor/drift.go — Page-Hinkley Drift Detection Engine
//
// Implements per-endpoint change-point detection using the Page-Hinkley (PH)
// test. The PH test is a sequential algorithm that detects upward shifts in
// the mean of a time series — in our case, the request count per time window
// for each API endpoint.
//
// Algorithm:
//   Given observations x₁, x₂, … xₙ:
//   Running Welford mean:  x̄ₜ = x̄ₜ₋₁ + (xₜ - x̄ₜ₋₁) / t
//   PH cumulative sum:     Uₜ = Uₜ₋₁ + xₜ - x̄ₜ - δ
//   PH score:              PHₜ = Uₜ - min(Uᵢ for i=1..t)
//   Alarm when:            PHₜ > λ
//
// The insensitivity parameter δ prevents false alarms from small fluctuations.
// The threshold λ controls how large a shift must be before an alarm fires.
//
// Zombie API detection: dormant endpoints (consecutive windows with zero
// requests) are labelled "dormant". When traffic suddenly appears on a dormant
// endpoint it is flagged as a potential resurrection/reconnaissance event.
//
// Sustained-attack escalation: if the same endpoint alarms for 2+ consecutive
// windows, the alarm_type is escalated to "sustained_attack" to distinguish
// ongoing automated scanners from one-off probe bursts.
package sensor

import (
	"context"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// DriftConfig holds tuning parameters for the Page-Hinkley detector.
type DriftConfig struct {
	// WindowDuration is the interval between PH evaluations (default: 10s).
	WindowDuration time.Duration
	// Delta is the PH insensitivity parameter δ (default: 0.005).
	// Smaller values make the detector more sensitive to small shifts.
	Delta float64
	// Lambda is the PH alarm threshold λ (default: 25.0).
	// Larger values require a larger cumulative shift before alarming.
	Lambda float64
	// MinDormantWins is the number of consecutive zero-request windows
	// before an endpoint is labelled "dormant" (default: 3).
	MinDormantWins int
}

// DefaultDriftConfig returns a DriftConfig tuned for API traffic monitoring.
func DefaultDriftConfig() DriftConfig {
	return DriftConfig{
		WindowDuration: 10 * time.Second,
		Delta:          0.005,
		Lambda:         25.0,
		MinDormantWins: 3,
	}
}

// phState holds per-endpoint Page-Hinkley state.
// Only the tick goroutine reads/writes this struct after initial insertion;
// no additional locking is required for these fields.
type phState struct {
	// Welford incremental mean
	n    int     // number of observations processed so far
	mean float64 // running mean x̄ₜ

	// Page-Hinkley accumulators
	cumSum float64 // Uₜ: PH cumulative sum
	minSum float64 // running minimum of cumSum for PH score calculation

	// Dormancy tracking
	dormCnt int  // consecutive windows with zero requests
	dormant bool // true when dormCnt >= MinDormantWins

	// Consecutive alarm tracking for sustained-attack escalation
	consecutiveAlarms int // windows in a row that exceeded the PH threshold
}

// observe updates PH state with a new observation x and returns (alarm, score).
//
// Welford mean update prevents numerical drift that would occur with a naive
// sum/count approach over long-running sensors.
func (ph *phState) observe(x, delta, lambda float64) (alarm bool, score float64) {
	ph.n++
	// Welford running mean: x̄ₜ = x̄ₜ₋₁ + (xₜ - x̄ₜ₋₁) / t
	ph.mean += (x - ph.mean) / float64(ph.n)

	// Page-Hinkley sum: Uₜ = Uₜ₋₁ + xₜ - x̄ₜ - δ
	ph.cumSum += x - ph.mean - delta

	// Track running minimum for PH score
	if ph.cumSum < ph.minSum {
		ph.minSum = ph.cumSum
	}

	// PH score: distance from current cumulative sum to its minimum
	score = ph.cumSum - ph.minSum
	alarm = score > lambda
	return
}

// DriftAlert is published to Redis when the PH detector fires.
// Consumed by remediation-brain to trigger incident response workflows.
type DriftAlert struct {
	EventType         string  `json:"event_type"`         // always "drift_alert"
	Endpoint          string  `json:"endpoint"`
	WindowCount       float64 `json:"window_count"`       // xₜ: requests in this window
	RunningMean       float64 `json:"running_mean"`       // x̄ₜ after this observation
	PHScore           float64 `json:"ph_score"`           // Uₜ - min(Uᵢ)
	Threshold         float64 `json:"threshold"`          // λ — for context in the brain
	WindowDurationSec float64 `json:"window_duration_sec"` // seconds per window (for rate calc)
	Resurrected       bool    `json:"resurrected"`        // was dormant, now active
	DormantWindows    int     `json:"dormant_windows"`    // consecutive zero windows before this
	AlarmType         string  `json:"alarm_type"`         // "resurrection" | "ph_threshold" | "resurrection+ph_threshold" | "sustained_attack"
	TimestampNs       int64   `json:"timestamp_ns"`
}

// EndpointStats is a snapshot of one endpoint's current drift state.
// Served by the /drift/stats HTTP endpoint consumed by intelligence-ui.
type EndpointStats struct {
	Endpoint       string  `json:"endpoint"`
	CurrentWindow  int64   `json:"current_window"`     // requests since last tick (not yet evaluated)
	RunningMean    float64 `json:"running_mean"`
	PHScore        float64 `json:"ph_score"`           // last computed score
	Dormant        bool    `json:"dormant"`
	DormantWindows int     `json:"dormant_windows"`
	TotalObs       int     `json:"total_observations"` // total windows evaluated
}

// DriftEngine manages per-endpoint Page-Hinkley change-point detectors.
//
// Hot path (Observe) is lock-free for already-registered endpoints using
// atomic.Int64 counters. New endpoint registration requires a brief write lock.
// The tick goroutine is the sole writer of phState structs (after initial
// insertion under lock), so no additional synchronisation is needed there.
//
// Stats() safety: phState fields (mean, dormant, etc.) are written exclusively
// by the tick goroutine. To avoid a data race between Stats() reads and tick
// writes, evaluate() stores a complete EndpointStats snapshot into lastStats
// under Lock. Stats() reads only from lastStats (and live atomic counters),
// never from phState directly.
type DriftEngine struct {
	mu        sync.RWMutex
	windows   map[string]*atomic.Int64 // hot path: lock-free per-endpoint request counter
	states    map[string]*phState      // PH state; written only by tick goroutine after init
	scores    map[string]float64       // last PH score per endpoint; for Stats()
	lastStats map[string]EndpointStats // latest EndpointStats snapshot; updated under Lock

	cfg DriftConfig
	log *zap.Logger
}

// NewDriftEngine creates a DriftEngine with the given configuration.
func NewDriftEngine(cfg DriftConfig, log *zap.Logger) *DriftEngine {
	return &DriftEngine{
		windows:   make(map[string]*atomic.Int64),
		states:    make(map[string]*phState),
		scores:    make(map[string]float64),
		lastStats: make(map[string]EndpointStats),
		cfg:       cfg,
		log:       log,
	}
}

// Observe records one request to the given endpoint path.
//
// Hot path: acquires RLock to check if the counter already exists (common case),
// falling through to a full Lock only for previously-unseen endpoints.
func (e *DriftEngine) Observe(path string) {
	e.mu.RLock()
	ctr, ok := e.windows[path]
	e.mu.RUnlock()

	if ok {
		ctr.Add(1)
		return
	}

	// New endpoint — promote to write lock and insert.
	e.mu.Lock()
	// Double-check: another goroutine may have inserted between RUnlock and Lock.
	if ctr, ok = e.windows[path]; ok {
		e.mu.Unlock()
		ctr.Add(1)
		return
	}
	var newCtr atomic.Int64
	newCtr.Store(1)
	e.windows[path] = &newCtr
	e.states[path] = &phState{}
	e.scores[path] = 0
	e.lastStats[path] = EndpointStats{Endpoint: path}
	e.mu.Unlock()
}

// Run starts the tick goroutine. It calls publishFn for each DriftAlert that fires.
// Blocks until ctx is cancelled.
func (e *DriftEngine) Run(ctx context.Context, publishFn func(context.Context, DriftAlert) error) {
	ticker := time.NewTicker(e.cfg.WindowDuration)
	defer ticker.Stop()

	e.log.Info("drift engine started",
		zap.Duration("window", e.cfg.WindowDuration),
		zap.Float64("delta", e.cfg.Delta),
		zap.Float64("lambda", e.cfg.Lambda),
		zap.Int("min_dormant_wins", e.cfg.MinDormantWins),
	)

	for {
		select {
		case <-ctx.Done():
			e.log.Info("drift engine stopping")
			return
		case <-ticker.C:
			alerts := e.tick()
			for _, alert := range alerts {
				if err := publishFn(ctx, alert); err != nil {
					e.log.Error("failed to publish drift alert",
						zap.String("endpoint", alert.Endpoint),
						zap.Error(err),
					)
				}
			}
		}
	}
}

// tick snapshots and resets all window counters, then evaluates PH for each
// endpoint. Returns all alerts that fired this tick.
//
// Counter drain uses atomic.Swap(0) which is safe to call from the tick
// goroutine while Observe() increments from other goroutines — no lost counts.
func (e *DriftEngine) tick() []DriftAlert {
	// Snapshot all endpoints and drain their counters atomically.
	e.mu.RLock()
	endpoints := make([]string, 0, len(e.windows))
	counts := make(map[string]float64, len(e.windows))
	for path, ctr := range e.windows {
		endpoints = append(endpoints, path)
		counts[path] = float64(ctr.Swap(0))
	}
	e.mu.RUnlock()

	var alerts []DriftAlert
	for _, path := range endpoints {
		if alert, fired := e.evaluate(path, counts[path]); fired {
			alerts = append(alerts, alert)
		}
	}
	return alerts
}

// evaluate runs the PH test for one endpoint with the given window count.
// Also handles dormancy detection and consecutive-alarm escalation.
//
// This method is only called from the tick goroutine, so phState access
// is safe without additional locking.
func (e *DriftEngine) evaluate(endpoint string, count float64) (DriftAlert, bool) {
	e.mu.RLock()
	ph := e.states[endpoint]
	e.mu.RUnlock()

	if ph == nil {
		return DriftAlert{}, false
	}

	wasDormant := ph.dormant

	// ── Dormancy update ────────────────────────────────────────────────────────
	if count == 0 {
		ph.dormCnt++
		if ph.dormCnt >= e.cfg.MinDormantWins {
			ph.dormant = true
		}
		// Reset consecutive alarm counter when traffic stops — avoids false
		// escalation of an endpoint that went dormant mid-alarm sequence.
		ph.consecutiveAlarms = 0

		// Update the lastStats snapshot so Stats() reflects current dormancy.
		// score is unchanged (last known value already in e.scores).
		e.mu.Lock()
		prevSnap := e.lastStats[endpoint]
		e.lastStats[endpoint] = EndpointStats{
			Endpoint:       endpoint,
			CurrentWindow:  0, // filled with live atomic value in Stats()
			RunningMean:    prevSnap.RunningMean,
			PHScore:        prevSnap.PHScore,
			Dormant:        ph.dormant,
			DormantWindows: ph.dormCnt,
			TotalObs:       ph.n,
		}
		e.mu.Unlock()
	} else {
		prevDormCnt := ph.dormCnt
		ph.dormCnt = 0

		// ── PH observation ─────────────────────────────────────────────────────
		alarm, score := ph.observe(count, e.cfg.Delta, e.cfg.Lambda)

		// ── Resurrection detection ─────────────────────────────────────────────
		resurrected := wasDormant && count > 0
		if resurrected {
			ph.dormant = false
		}

		// ── Consecutive alarm tracking ─────────────────────────────────────────
		if alarm {
			ph.consecutiveAlarms++
		} else {
			ph.consecutiveAlarms = 0
		}

		// Store score AND a complete stats snapshot for Stats() queries.
		// Written AFTER resurrection/alarm state is finalised so the snapshot
		// reflects the post-update values (dormant cleared, counts correct).
		// By writing to lastStats under Lock here (tick goroutine only), Stats()
		// can safely read lastStats under RLock without touching phState at all —
		// eliminating the data race on ph.mean / ph.dormant / ph.n etc.
		e.mu.Lock()
		e.scores[endpoint] = score
		e.lastStats[endpoint] = EndpointStats{
			Endpoint:       endpoint,
			CurrentWindow:  0, // filled with live atomic value in Stats()
			RunningMean:    math.Round(ph.mean*1000) / 1000,
			PHScore:        math.Round(score*1000) / 1000,
			Dormant:        ph.dormant,
			DormantWindows: ph.dormCnt,
			TotalObs:       ph.n,
		}
		e.mu.Unlock()

		// ── Determine alarm type ───────────────────────────────────────────────
		shouldAlert := resurrected || alarm
		if !shouldAlert {
			return DriftAlert{}, false
		}

		alarmType := ""
		switch {
		case ph.consecutiveAlarms >= 2:
			// Same endpoint alarmed for 2+ consecutive windows — escalate.
			alarmType = "sustained_attack"
		case resurrected && alarm:
			alarmType = "resurrection+ph_threshold"
		case resurrected:
			alarmType = "resurrection"
		default:
			alarmType = "ph_threshold"
		}

		e.log.Warn("drift alarm fired",
			zap.String("endpoint", endpoint),
			zap.String("alarm_type", alarmType),
			zap.Float64("count", count),
			zap.Float64("mean", ph.mean),
			zap.Float64("ph_score", score),
			zap.Bool("resurrected", resurrected),
			zap.Int("dormant_windows_before", prevDormCnt),
			zap.Int("consecutive_alarms", ph.consecutiveAlarms),
		)

		return DriftAlert{
			EventType:         "drift_alert",
			Endpoint:          endpoint,
			WindowCount:       count,
			RunningMean:       ph.mean,
			PHScore:           math.Round(score*1000) / 1000, // 3 decimal places
			Threshold:         e.cfg.Lambda,
			WindowDurationSec: e.cfg.WindowDuration.Seconds(),
			Resurrected:       resurrected,
			DormantWindows:    prevDormCnt,
			AlarmType:         alarmType,
			TimestampNs:       time.Now().UnixNano(),
		}, true
	}

	return DriftAlert{}, false
}

// Stats returns a snapshot of all endpoint drift states.
// Called from the /drift/stats HTTP handler; acquires RLock for a consistent read.
//
// Race-free design: phState fields are NOT read here. Instead, evaluate() writes
// a complete EndpointStats snapshot into lastStats under Lock every tick window.
// Stats() copies from lastStats (protected by RLock) and merges in the live
// CurrentWindow counter from the atomic.Int64 (atomic load is always safe).
func (e *DriftEngine) Stats() []EndpointStats {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make([]EndpointStats, 0, len(e.windows))
	for path, ctr := range e.windows {
		snap, ok := e.lastStats[path]
		if !ok {
			continue
		}
		// Merge live current-window count (atomic, safe without mutex).
		snap.CurrentWindow = ctr.Load()
		result = append(result, snap)
	}
	return result
}

// Reset clears the PH state for an endpoint after successful remediation.
// Called by the remediation-brain via a future control plane API.
// The next observation will re-initialise the state from scratch.
func (e *DriftEngine) Reset(endpoint string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.states[endpoint]; ok {
		e.states[endpoint] = &phState{}
		e.scores[endpoint] = 0
		e.lastStats[endpoint] = EndpointStats{Endpoint: endpoint}
		e.log.Info("drift state reset", zap.String("endpoint", endpoint))
	}
}
