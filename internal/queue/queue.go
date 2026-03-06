package queue

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"smtp-server/internal/config"
)

type Status string

const (
	StatusPending   Status = "pending"
	StatusInflight  Status = "inflight"
	StatusDeferred  Status = "deferred"
	StatusDelivered Status = "delivered"
	StatusFailed    Status = "failed"
)

// Message represents a queued email.
type Message struct {
	ID         string    `json:"id"`
	Username   string    `json:"username,omitempty"`
	From       string    `json:"from"`
	To         []string  `json:"to"`
	Data       []byte    `json:"data"`
	Status     Status    `json:"status"`
	RetryCount int       `json:"retry_count"`
	NextRetry  time.Time `json:"next_retry"`
	CreatedAt  time.Time `json:"created_at"`
	LastError  string    `json:"last_error,omitempty"`
}

// Queue is a file-based persistent message queue.
type Queue struct {
	dir      string
	mu       sync.Mutex
	inflight map[string]bool
	ready    chan struct{}
}

// New creates a Queue backed by the given directory.
// Any messages left in-flight from a previous run are reset to pending.
func New(cfg config.QueueConfig) *Queue {
	os.MkdirAll(cfg.Dir, 0755)
	os.MkdirAll(filepath.Join(cfg.Dir, "failed"), 0755)

	q := &Queue{
		dir:      cfg.Dir,
		inflight: make(map[string]bool),
		ready:    make(chan struct{}, 1),
	}
	q.resetInflight()
	go q.scanner()
	return q
}

// Enqueue persists a new message and signals workers.
func (q *Queue) Enqueue(msg *Message) error {
	if msg.ID == "" {
		id, err := generateID()
		if err != nil {
			return fmt.Errorf("generate id: %w", err)
		}
		msg.ID = id
	}
	msg.Status = StatusPending
	msg.CreatedAt = time.Now()

	q.mu.Lock()
	err := q.save(msg)
	q.mu.Unlock()

	if err != nil {
		return err
	}
	q.signal()
	return nil
}

// Pop returns the next message ready for delivery, or nil if none available.
// The returned message is marked in-flight so other workers skip it.
func (q *Queue) Pop() *Message {
	q.mu.Lock()
	defer q.mu.Unlock()

	entries, err := os.ReadDir(q.dir)
	if err != nil {
		return nil
	}

	now := time.Now()
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		id := entry.Name()[:len(entry.Name())-5]
		if q.inflight[id] {
			continue
		}

		data, err := os.ReadFile(filepath.Join(q.dir, entry.Name()))
		if err != nil {
			continue
		}
		var msg Message
		if err := json.Unmarshal(data, &msg); err != nil {
			continue
		}

		if msg.Status == StatusPending ||
			(msg.Status == StatusDeferred && now.After(msg.NextRetry)) {
			msg.Status = StatusInflight
			if err := q.save(&msg); err != nil {
				continue
			}
			q.inflight[msg.ID] = true
			return &msg
		}
	}
	return nil
}

// Ready returns a channel that receives a signal when messages may be ready.
func (q *Queue) Ready() <-chan struct{} {
	return q.ready
}

// Complete removes a successfully delivered message from the queue.
func (q *Queue) Complete(id string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	delete(q.inflight, id)
	os.Remove(q.msgPath(id))
}

// Defer reschedules a message for later retry and increments the retry counter.
func (q *Queue) Defer(msg *Message, retryAfter time.Duration, lastError string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	delete(q.inflight, msg.ID)
	msg.Status = StatusDeferred
	msg.RetryCount++
	msg.NextRetry = time.Now().Add(retryAfter)
	msg.LastError = lastError
	if err := q.save(msg); err != nil {
		log.Printf("queue: failed to defer message %s: %v", msg.ID, err)
	}
}

// DeferNoIncrement reschedules a message for later retry WITHOUT incrementing
// the retry counter. Used for 421 rate-limit deferrals so MaxRetries is
// reserved for real SMTP failures.
func (q *Queue) DeferNoIncrement(msg *Message, retryAfter time.Duration, lastError string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	delete(q.inflight, msg.ID)
	msg.Status = StatusDeferred
	// RetryCount intentionally not incremented.
	msg.NextRetry = time.Now().Add(retryAfter)
	msg.LastError = lastError
	if err := q.save(msg); err != nil {
		log.Printf("queue: failed to defer (no-inc) message %s: %v", msg.ID, err)
	}
}

// Fail permanently fails a message and moves it to the failed/ subdirectory.
func (q *Queue) Fail(msg *Message, reason string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	delete(q.inflight, msg.ID)
	msg.Status = StatusFailed
	msg.LastError = reason

	data, _ := json.MarshalIndent(msg, "", "  ")
	os.WriteFile(filepath.Join(q.dir, "failed", msg.ID+".json"), data, 0644)
	os.Remove(q.msgPath(msg.ID))
}

// CancelByMessageID removes a message from the queue by its ID.
func (q *Queue) CancelByMessageID(msgID string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	delete(q.inflight, msgID)
	os.Remove(q.msgPath(msgID))
}

// resetInflight resets any in-flight messages from a previous run to pending.
func (q *Queue) resetInflight() {
	entries, err := os.ReadDir(q.dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(q.dir, entry.Name()))
		if err != nil {
			continue
		}
		var msg Message
		if err := json.Unmarshal(data, &msg); err != nil {
			continue
		}
		if msg.Status == StatusInflight {
			msg.Status = StatusPending
			q.save(&msg)
		}
	}
}

// scanner periodically wakes workers so deferred messages get retried.
func (q *Queue) scanner() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		q.signal()
	}
}

func (q *Queue) signal() {
	select {
	case q.ready <- struct{}{}:
	default:
	}
}

func (q *Queue) save(msg *Message) error {
	data, err := json.MarshalIndent(msg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(q.msgPath(msg.ID), data, 0644)
}

func (q *Queue) msgPath(id string) string {
	return filepath.Join(q.dir, id+".json")
}

// Stats holds queue counts per status.
type Stats struct {
	Pending  int `json:"pending"`
	Inflight int `json:"inflight"`
	Deferred int `json:"deferred"`
	Failed   int `json:"failed"`
	Total    int `json:"total"`
}

// Stats returns a snapshot of message counts by status.
func (q *Queue) Stats() Stats {
	q.mu.Lock()
	defer q.mu.Unlock()

	var s Stats
	entries, err := os.ReadDir(q.dir)
	if err != nil {
		return s
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(q.dir, entry.Name()))
		if err != nil {
			continue
		}
		var msg Message
		if err := json.Unmarshal(data, &msg); err != nil {
			continue
		}
		switch msg.Status {
		case StatusPending:
			s.Pending++
		case StatusInflight:
			s.Inflight++
		case StatusDeferred:
			s.Deferred++
		}
		s.Total++
	}

	// Count failed messages in the failed/ subdirectory.
	failedEntries, err := os.ReadDir(filepath.Join(q.dir, "failed"))
	if err == nil {
		for _, e := range failedEntries {
			if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
				s.Failed++
			}
		}
	}
	return s
}

func generateID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%d-%s", time.Now().UnixNano(), hex.EncodeToString(b[:8])), nil
}
