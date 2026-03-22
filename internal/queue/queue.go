package queue

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
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

// queueUserKey maps a username to a filesystem-safe subdirectory (per-user queue bucket).
func queueUserKey(username string) string {
	s := strings.TrimSpace(username)
	if s == "" {
		return "_system"
	}
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '/', '\\', ':', '*', '?', '"', '<', '>', '|', 0:
			b.WriteByte('_')
		default:
			if r < 32 {
				b.WriteByte('_')
			} else {
				b.WriteRune(r)
			}
		}
	}
	s = strings.ToLower(b.String())
	s = strings.Trim(s, ".")
	if s == "" || s == "." || s == ".." || strings.EqualFold(s, "failed") {
		return "_user"
	}
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}

// Queue is a file-based persistent message queue.
type Queue struct {
	dir          string
	mu           sync.Mutex
	inflight map[string]bool
	ready    chan struct{}
	rrIdx    int // round-robin cursor across user queue buckets
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
// Same fairness as PopFair (round-robin across users). Prefer PopFairBatch via the delivery dispatcher.
func (q *Queue) Pop() *Message {
	return q.PopFair()
}

// Ready returns a channel that receives a signal when messages may be ready.
func (q *Queue) Ready() <-chan struct{} {
	return q.ready
}

type fairCandidate struct {
	msg      Message
	fullPath string // absolute path to the JSON file on disk
}

func sortUserKeys(m map[string][]fairCandidate) []string {
	users := make([]string, 0, len(m))
	for u := range m {
		users = append(users, u)
	}
	for i := 1; i < len(users); i++ {
		for j := i; j > 0 && users[j] < users[j-1]; j-- {
			users[j], users[j-1] = users[j-1], users[j]
		}
	}
	return users
}

// collectReadyCandidatesLocked scans per-user subdirs plus legacy root files.
// Caller must hold q.mu.
func (q *Queue) collectReadyCandidatesLocked(now time.Time) map[string][]fairCandidate {
	byUser := make(map[string][]fairCandidate)
	entries, err := os.ReadDir(q.dir)
	if err != nil {
		return byUser
	}

	tryAppend := func(fullPath, fname string) {
		if filepath.Ext(fname) != ".json" {
			return
		}
		id := strings.TrimSuffix(fname, ".json")
		if q.inflight[id] {
			return
		}
		data, err := os.ReadFile(fullPath)
		if err != nil {
			return
		}
		var msg Message
		if err := json.Unmarshal(data, &msg); err != nil {
			return
		}
		if msg.Status != StatusPending &&
			!(msg.Status == StatusDeferred && now.After(msg.NextRetry)) {
			return
		}
		key := queueUserKey(msg.Username)
		byUser[key] = append(byUser[key], fairCandidate{msg: msg, fullPath: fullPath})
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if name == "failed" {
			continue
		}
		subDir := filepath.Join(q.dir, name)
		subFiles, err := os.ReadDir(subDir)
		if err != nil {
			continue
		}
		for _, f := range subFiles {
			if f.IsDir() {
				continue
			}
			tryAppend(filepath.Join(subDir, f.Name()), f.Name())
		}
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		tryAppend(filepath.Join(q.dir, entry.Name()), entry.Name())
	}

	return byUser
}

// popFairBatchLocked claims up to maxN messages with strong fairness:
// each sweep takes at most one ready message per user, then rotates start user.
// Queue files live under queue/<userKey>/id.json (legacy root id.json still read).
func (q *Queue) popFairBatchLocked(maxN int) []*Message {
	if maxN <= 0 {
		maxN = 1
	}

	now := time.Now()
	byUser := q.collectReadyCandidatesLocked(now)

	var out []*Message
	for len(out) < maxN && len(byUser) > 0 {
		users := sortUserKeys(byUser)
		nU := len(users)
		if nU == 0 {
			break
		}
		if q.rrIdx >= nU {
			q.rrIdx = 0
		}

		madeProgress := false
		for step := 0; step < nU && len(out) < maxN; step++ {
			ui := (q.rrIdx + step) % nU
			picked := users[ui]
			cands := byUser[picked]
			if len(cands) == 0 {
				delete(byUser, picked)
				continue
			}

			bestIdx := 0
			for i := 1; i < len(cands); i++ {
				if cands[i].msg.CreatedAt.Before(cands[bestIdx].msg.CreatedAt) {
					bestIdx = i
				}
			}
			best := cands[bestIdx]
			cands[bestIdx] = cands[len(cands)-1]
			cands = cands[:len(cands)-1]
			if len(cands) == 0 {
				delete(byUser, picked)
			} else {
				byUser[picked] = cands
			}

			msg := best.msg
			msg.Status = StatusInflight
			if err := q.saveRelocating(&msg, best.fullPath); err != nil {
				log.Printf("queue: failed to claim message %s: %v", msg.ID, err)
				continue
			}
			q.inflight[msg.ID] = true
			ptr := new(Message)
			*ptr = msg
			out = append(out, ptr)
			madeProgress = true
		}

		q.rrIdx = (q.rrIdx + 1) % nU
		if !madeProgress {
			break
		}
	}
	return out
}

// PopFair returns the next message using round-robin user scheduling so that
// no single user monopolises the workers when multiple users have queued mail.
// Falls back to FIFO if all users have only one message or no username is set.
func (q *Queue) PopFair() *Message {
	q.mu.Lock()
	defer q.mu.Unlock()
	batch := q.popFairBatchLocked(1)
	if len(batch) == 0 {
		return nil
	}
	return batch[0]
}

// PopFairBatch claims up to maxN ready messages in a single directory scan.
// Used by the delivery dispatcher to avoid N×disk scans when many workers drain the queue.
func (q *Queue) PopFairBatch(maxN int) []*Message {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.popFairBatchLocked(maxN)
}

// Complete removes a successfully delivered message from the queue.
func (q *Queue) Complete(id string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	delete(q.inflight, id)
	_ = os.Remove(q.findMessageFileLocked(id))
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
	if err := q.saveRelocating(msg, q.findMessageFileLocked(msg.ID)); err != nil {
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
	if err := q.saveRelocating(msg, q.findMessageFileLocked(msg.ID)); err != nil {
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
	_ = os.WriteFile(filepath.Join(q.dir, "failed", msg.ID+".json"), data, 0644)
	_ = os.Remove(q.findMessageFileLocked(msg.ID))
}

// CancelByMessageID removes a message from the queue by its ID.
func (q *Queue) CancelByMessageID(msgID string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	delete(q.inflight, msgID)
	_ = os.Remove(q.findMessageFileLocked(msgID))
}

// ClearAll removes all messages from the queue (pending, deferred, failed).
// Returns the number of messages removed.
func (q *Queue) ClearAll() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.inflight = make(map[string]bool)
	count := 0
	entries, err := os.ReadDir(q.dir)
	if err != nil {
		return 0
	}
	for _, entry := range entries {
		name := entry.Name()
		if name == "failed" {
			continue
		}
		if entry.IsDir() {
			sub := filepath.Join(q.dir, name)
			files, err := os.ReadDir(sub)
			if err != nil {
				continue
			}
			for _, f := range files {
				if f.IsDir() || filepath.Ext(f.Name()) != ".json" {
					continue
				}
				if err := os.Remove(filepath.Join(sub, f.Name())); err == nil {
					count++
				}
			}
			_ = os.Remove(sub)
			continue
		}
		if filepath.Ext(name) == ".json" {
			if err := os.Remove(filepath.Join(q.dir, name)); err == nil {
				count++
			}
		}
	}
	failedDir := filepath.Join(q.dir, "failed")
	if failedEntries, err := os.ReadDir(failedDir); err == nil {
		for _, e := range failedEntries {
			if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
				if err := os.Remove(filepath.Join(failedDir, e.Name())); err == nil {
					count++
				}
			}
		}
	}
	return count
}

// ClearByUser removes all messages for that username from the queue.
// Returns the number of messages removed.
func (q *Queue) ClearByUser(username string) int {
	q.mu.Lock()
	defer q.mu.Unlock()
	count := 0
	key := queueUserKey(username)
	sub := filepath.Join(q.dir, key)
	if files, err := os.ReadDir(sub); err == nil {
		for _, f := range files {
			if f.IsDir() || filepath.Ext(f.Name()) != ".json" {
				continue
			}
			id := strings.TrimSuffix(f.Name(), ".json")
			delete(q.inflight, id)
			if err := os.Remove(filepath.Join(sub, f.Name())); err == nil {
				count++
			}
		}
		_ = os.Remove(sub)
	}
	entries, err := os.ReadDir(q.dir)
	if err != nil {
		return count
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		data, err := os.ReadFile(filepath.Join(q.dir, entry.Name()))
		if err != nil {
			continue
		}
		var msg Message
		if err := json.Unmarshal(data, &msg); err != nil {
			continue
		}
		if msg.Username == username {
			delete(q.inflight, id)
			if err := os.Remove(filepath.Join(q.dir, entry.Name())); err == nil {
				count++
			}
		}
	}
	failedDir := filepath.Join(q.dir, "failed")
	if failedEntries, err := os.ReadDir(failedDir); err == nil {
		for _, e := range failedEntries {
			if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
				continue
			}
			data, err := os.ReadFile(filepath.Join(failedDir, e.Name()))
			if err != nil {
				continue
			}
			var msg Message
			if err := json.Unmarshal(data, &msg); err != nil {
				continue
			}
			if msg.Username == username {
				if err := os.Remove(filepath.Join(failedDir, e.Name())); err == nil {
					count++
				}
			}
		}
	}
	return count
}

// resetInflight resets any in-flight messages from a previous run to pending.
func (q *Queue) resetInflight() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.resetInflightLocked()
}

func (q *Queue) resetInflightLocked() {
	entries, err := os.ReadDir(q.dir)
	if err != nil {
		return
	}
	resetFile := func(fullPath string) {
		data, err := os.ReadFile(fullPath)
		if err != nil {
			return
		}
		var msg Message
		if err := json.Unmarshal(data, &msg); err != nil {
			return
		}
		if msg.Status == StatusInflight {
			msg.Status = StatusPending
			_ = q.saveRelocating(&msg, fullPath)
		}
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			if filepath.Ext(entry.Name()) == ".json" {
				resetFile(filepath.Join(q.dir, entry.Name()))
			}
			continue
		}
		if entry.Name() == "failed" {
			continue
		}
		sub := filepath.Join(q.dir, entry.Name())
		files, err := os.ReadDir(sub)
		if err != nil {
			continue
		}
		for _, f := range files {
			if f.IsDir() || filepath.Ext(f.Name()) != ".json" {
				continue
			}
			resetFile(filepath.Join(sub, f.Name()))
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

func (q *Queue) messageFilePath(msg *Message) string {
	key := queueUserKey(msg.Username)
	return filepath.Join(q.dir, key, msg.ID+".json")
}

// findMessageFileLocked returns the path to id.json (legacy root or per-user subdir).
// Caller must hold q.mu (or run at init before other goroutines).
func (q *Queue) findMessageFileLocked(id string) string {
	legacy := filepath.Join(q.dir, id+".json")
	if st, err := os.Stat(legacy); err == nil && !st.IsDir() {
		return legacy
	}
	entries, err := os.ReadDir(q.dir)
	if err != nil {
		return legacy
	}
	for _, e := range entries {
		if !e.IsDir() || e.Name() == "failed" {
			continue
		}
		p := filepath.Join(q.dir, e.Name(), id+".json")
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return legacy
}

func (q *Queue) save(msg *Message) error {
	return q.saveRelocating(msg, "")
}

func (q *Queue) saveRelocating(msg *Message, previousPath string) error {
	newPath := q.messageFilePath(msg)
	data, err := json.MarshalIndent(msg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(newPath), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(newPath, data, 0644); err != nil {
		return err
	}
	legacyPath := filepath.Join(q.dir, msg.ID+".json")
	if legacyPath != newPath {
		_ = os.Remove(legacyPath)
	}
	if previousPath != "" && previousPath != newPath {
		_ = os.Remove(previousPath)
	}
	return nil
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
	countFile := func(fullPath string) {
		data, err := os.ReadFile(fullPath)
		if err != nil {
			return
		}
		var msg Message
		if err := json.Unmarshal(data, &msg); err != nil {
			return
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
	for _, entry := range entries {
		if !entry.IsDir() {
			if filepath.Ext(entry.Name()) == ".json" {
				countFile(filepath.Join(q.dir, entry.Name()))
			}
			continue
		}
		if entry.Name() == "failed" {
			continue
		}
		sub := filepath.Join(q.dir, entry.Name())
		files, err := os.ReadDir(sub)
		if err != nil {
			continue
		}
		for _, f := range files {
			if f.IsDir() || filepath.Ext(f.Name()) != ".json" {
				continue
			}
			countFile(filepath.Join(sub, f.Name()))
		}
	}

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
