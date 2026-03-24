package delivery

import (
	"sync"
	"time"
)

const metricsBucketCount = 12 // 12 × 5s = 60s rolling window

type metricCounts struct {
	Attempts   uint64 `json:"attempts"`
	Delivered  uint64 `json:"delivered"`
	Deferred   uint64 `json:"deferred"`
	Failed     uint64 `json:"failed"`
	HardBounce uint64 `json:"hard_bounce"`
	Suppressed uint64 `json:"suppressed"`
}

// deliveryMetrics tracks per-outcome counts for live monitoring (admin JSON + UI).
type deliveryMetrics struct {
	mu        sync.Mutex
	started   time.Time
	bucketIdx int
	buckets   [metricsBucketCount]metricCounts
	lifetime  metricCounts
}

func newDeliveryMetrics() *deliveryMetrics {
	return &deliveryMetrics{started: time.Now()}
}

func (m *deliveryMetrics) rotateBucket() {
	m.mu.Lock()
	m.bucketIdx = (m.bucketIdx + 1) % metricsBucketCount
	m.buckets[m.bucketIdx] = metricCounts{}
	m.mu.Unlock()
}

func (m *deliveryMetrics) recordAttempt() {
	m.mu.Lock()
	m.lifetime.Attempts++
	m.buckets[m.bucketIdx].Attempts++
	m.mu.Unlock()
}

func (m *deliveryMetrics) recordStatus(status string) {
	m.mu.Lock()
	switch status {
	case "delivered":
		m.lifetime.Delivered++
		m.buckets[m.bucketIdx].Delivered++
	case "deferred":
		m.lifetime.Deferred++
		m.buckets[m.bucketIdx].Deferred++
	case "failed":
		m.lifetime.Failed++
		m.buckets[m.bucketIdx].Failed++
	case "hard_bounce":
		m.lifetime.HardBounce++
		m.buckets[m.bucketIdx].HardBounce++
	case "suppressed":
		m.lifetime.Suppressed++
		m.buckets[m.bucketIdx].Suppressed++
	}
	m.mu.Unlock()
}

// MetricsSnapshot is JSON-serializable live telemetry.
type MetricsSnapshot struct {
	UptimeSec int64 `json:"uptime_sec"`

	Lifetime metricCounts `json:"lifetime"`

	// Rolling60s sums the last 12 buckets (60 seconds).
	Rolling60s metricCounts `json:"rolling_60s"`

	// PerMinute matches Rolling60s (rough events-per-minute view for the last ~60s).
	PerMinute metricCounts `json:"per_minute"`
}

func (m *deliveryMetrics) Snapshot() MetricsSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()

	var roll metricCounts
	for i := 0; i < metricsBucketCount; i++ {
		roll.Attempts += m.buckets[i].Attempts
		roll.Delivered += m.buckets[i].Delivered
		roll.Deferred += m.buckets[i].Deferred
		roll.Failed += m.buckets[i].Failed
		roll.HardBounce += m.buckets[i].HardBounce
		roll.Suppressed += m.buckets[i].Suppressed
	}

	return MetricsSnapshot{
		UptimeSec:  int64(time.Since(m.started).Seconds()),
		Lifetime:   m.lifetime,
		Rolling60s: roll,
		PerMinute:  roll,
	}
}

func (e *Engine) startMetricsRotator() {
	if e.metrics == nil {
		return
	}
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for range t.C {
			e.metrics.rotateBucket()
		}
	}()
}

// RecordDeliveryTelemetry counts a finished outcome (after DB hook).
func (e *Engine) RecordDeliveryTelemetry(status string) {
	if e.metrics == nil {
		return
	}
	e.metrics.recordStatus(status)
}

// RecordDeliveryAttempt counts one worker starting deliver() for a message.
func (e *Engine) RecordDeliveryAttempt() {
	if e.metrics == nil {
		return
	}
	e.metrics.recordAttempt()
}

// MetricsSnapshot returns lifetime + last-60s delivery counters.
func (e *Engine) MetricsSnapshot() MetricsSnapshot {
	if e.metrics == nil {
		return MetricsSnapshot{}
	}
	return e.metrics.Snapshot()
}

// DispatchQueueDepth returns buffered messages waiting for workers (0 if engine not started).
func (e *Engine) DispatchQueueDepth() (queued int, capacity int) {
	if e.workCh == nil {
		return 0, 0
	}
	return len(e.workCh), cap(e.workCh)
}

// WorkerCount returns configured delivery workers.
func (e *Engine) WorkerCount() int {
	n := e.cfg.Workers
	if n < 1 {
		return 1
	}
	return n
}
