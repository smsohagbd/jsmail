package delivery

import (
	"fmt"
	"sort"
	"time"

	"smtp-server/internal/queue"
)

// deliveryTrace is one message currently inside deliver() (worker busy).
type deliveryTrace struct {
	MessageID string
	Username  string
	From      string
	ToPreview string
	Domain    string
	Phase     string
	Detail    string
	StartedAt time.Time
	UpdatedAt time.Time
}

// DeliveryTracePublic is JSON-safe telemetry for admin (why is this send slow?).
type DeliveryTracePublic struct {
	MessageID               string    `json:"message_id"`
	Username                string    `json:"username"`
	From                    string    `json:"from"`
	ToPreview               string    `json:"to_preview"`
	Domain                  string    `json:"domain"`
	Phase                   string    `json:"phase"`
	Detail                  string    `json:"detail"`
	StartedAt               time.Time `json:"started_at"`
	UpdatedAt               time.Time `json:"updated_at"`
	SecondsSinceStart       float64   `json:"seconds_since_start"`
	SecondsSincePhaseUpdate float64   `json:"seconds_since_phase_update"`
}

func (e *Engine) traceStart(msg *queue.Message) {
	if e == nil || msg == nil {
		return
	}
	t := &deliveryTrace{
		MessageID: msg.ID,
		Username:  msg.Username,
		From:      msg.From,
		StartedAt: time.Now(),
		UpdatedAt: time.Now(),
		Phase:     "deliver_started",
		Detail:    fmt.Sprintf("retry_count=%d to=%d_rcpt", msg.RetryCount, len(msg.To)),
	}
	if len(msg.To) > 0 {
		t.ToPreview = msg.To[0]
		if len(msg.To) > 1 {
			t.ToPreview += fmt.Sprintf(" +%d", len(msg.To)-1)
		}
	}
	e.traceMu.Lock()
	if e.activeTraces == nil {
		e.activeTraces = make(map[string]*deliveryTrace)
	}
	e.activeTraces[msg.ID] = t
	e.traceMu.Unlock()
}

func (e *Engine) traceEnd(id string) {
	if e == nil || id == "" {
		return
	}
	e.traceMu.Lock()
	delete(e.activeTraces, id)
	e.traceMu.Unlock()
}

func (e *Engine) tracePhase(id, phase, detail string) {
	if e == nil || id == "" {
		return
	}
	e.traceMu.Lock()
	if t := e.activeTraces[id]; t != nil {
		t.Phase = phase
		t.Detail = detail
		t.UpdatedAt = time.Now()
	}
	e.traceMu.Unlock()
}

func (e *Engine) traceDomain(id, domain string) {
	if e == nil || id == "" {
		return
	}
	e.traceMu.Lock()
	if t := e.activeTraces[id]; t != nil {
		t.Domain = domain
		t.UpdatedAt = time.Now()
	}
	e.traceMu.Unlock()
}

// ActiveDeliveryTraces returns workers currently inside deliver(), newest phase update first.
func (e *Engine) ActiveDeliveryTraces() []DeliveryTracePublic {
	if e == nil {
		return nil
	}
	e.traceMu.Lock()
	list := make([]*deliveryTrace, 0, len(e.activeTraces))
	for _, t := range e.activeTraces {
		list = append(list, t)
	}
	e.traceMu.Unlock()

	sort.Slice(list, func(i, j int) bool {
		return list[i].UpdatedAt.After(list[j].UpdatedAt)
	})
	now := time.Now()
	out := make([]DeliveryTracePublic, len(list))
	for i, t := range list {
		out[i] = DeliveryTracePublic{
			MessageID:               t.MessageID,
			Username:                t.Username,
			From:                    t.From,
			ToPreview:               t.ToPreview,
			Domain:                  t.Domain,
			Phase:                   t.Phase,
			Detail:                  t.Detail,
			StartedAt:               t.StartedAt,
			UpdatedAt:               t.UpdatedAt,
			SecondsSinceStart:       now.Sub(t.StartedAt).Seconds(),
			SecondsSincePhaseUpdate: now.Sub(t.UpdatedAt).Seconds(),
		}
	}
	return out
}
