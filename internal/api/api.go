package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	appdb "smtp-server/internal/db"
	"smtp-server/internal/email"
	"smtp-server/internal/config"
	"smtp-server/internal/queue"
	"smtp-server/internal/verifier"
)

// Server exposes an HTTP API for injecting messages into the queue.
type Server struct {
	cfg       config.APIConfig
	queue     *queue.Queue
	verifier  *verifier.Verifier
	startedAt time.Time
}

func New(cfg config.APIConfig, q *queue.Queue, heloName string) *Server {
	v := verifier.New(verifier.Config{
		HeloName:       heloName,
		ConnectTimeout: 10 * time.Second,
	})
	return &Server{cfg: cfg, queue: q, verifier: v, startedAt: time.Now()}
}

func (s *Server) Start() {
	mux := http.NewServeMux()
	mux.HandleFunc("/send", s.requireAuth(s.handleSend))
	mux.HandleFunc("/verify", s.requireAuth(s.handleVerify))
	mux.HandleFunc("/verify/bulk", s.requireAuth(s.handleVerifyBulk))
	mux.HandleFunc("/health", s.handleHealth)

	log.Printf("api: HTTP server listening on %s", s.cfg.ListenAddr)
	if err := http.ListenAndServe(s.cfg.ListenAddr, mux); err != nil {
		log.Fatalf("api: server failed: %v", err)
	}
}

// requireAuth checks the Authorization: Bearer <token> header.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.AuthToken != "" {
			auth := r.Header.Get("Authorization")
			if auth != "Bearer "+s.cfg.AuthToken {
				log.Printf("[API] ✗ unauthorized request from %s (bad/missing token)", r.RemoteAddr)
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
				return
			}
		}
		next(w, r)
	}
}

// SendRequest is the JSON body for POST /send.
type SendRequest struct {
	From    string   `json:"from"`
	To      []string `json:"to"`
	Subject string   `json:"subject"`
	Body    string   `json:"body"`
	HTML    bool     `json:"html"`
	// RawData allows submitting a pre-built RFC 5322 message (base64 not required; plain string).
	RawData string `json:"raw_data"`
}

// SendResponse is the JSON response for POST /send.
type SendResponse struct {
	MessageID string `json:"message_id"`
	Status    string `json:"status"`
}

func (s *Server) handleSend(w http.ResponseWriter, r *http.Request) {
	ip := r.RemoteAddr
	log.Printf("[API] ▶ POST /send from %s", ip)

	if r.Method != http.MethodPost {
		log.Printf("[API] ✗ wrong method %s from %s", r.Method, ip)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	var req SendRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("[API] ✗ invalid JSON from %s: %v", ip, err)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if req.From == "" {
		log.Printf("[API] ✗ missing 'from' field from %s", ip)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "from is required"})
		return
	}
	if len(req.To) == 0 {
		log.Printf("[API] ✗ missing 'to' field from %s", ip)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "to is required"})
		return
	}

	var data []byte
	if req.RawData != "" {
		data = []byte(req.RawData)
		log.Printf("[API]   using raw RFC5322 message (%d bytes)", len(data))
	} else {
		if req.Subject == "" {
			log.Printf("[API] ✗ missing 'subject' field from %s", ip)
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "subject is required (or provide raw_data)"})
			return
		}
		data = buildRFC5322(req)
		log.Printf("[API]   built RFC5322 message (%d bytes)", len(data))
	}

	from := req.From
	if newFrom, applied := appdb.ApplyForceAddress(req.From); applied {
		from = newFrom
		data = email.RewriteFromHeader(data, from)
		log.Printf("[API]   force-from/email applied  new_from=%s", from)
	}
	if appdb.GetForceEmailEnabled() {
		forceSubj := appdb.GetForceEmailSubject()
		forceBody := appdb.GetForceEmailBody()
		if forceSubj != "" || forceBody != "" {
			data = email.RewriteSubjectAndBody(data, forceSubj, forceBody)
		}
	}

	msg := &queue.Message{
		From: from,
		To:   req.To,
		Data: data,
	}
	if err := s.queue.Enqueue(msg); err != nil {
		log.Printf("[API] ✗ enqueue failed from %s: %v", ip, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to queue message"})
		return
	}

	log.Printf("[API] ✓ queued  id=%s  from=%s  to=%v  (requested by %s)", msg.ID, msg.From, msg.To, ip)
	writeJSON(w, http.StatusAccepted, SendResponse{MessageID: msg.ID, Status: "queued"})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	log.Printf("[API]   GET /health from %s", r.RemoteAddr)

	uptime := time.Since(s.startedAt)
	qStats := s.queue.Stats()

	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"version": "1.0.0",
		"uptime":  formatUptime(uptime),
		"uptime_seconds": int(uptime.Seconds()),
		"started_at": s.startedAt.UTC().Format(time.RFC3339),
		"queue": map[string]any{
			"pending":  qStats.Pending,
			"inflight": qStats.Inflight,
			"deferred": qStats.Deferred,
			"failed":   qStats.Failed,
			"total":    qStats.Total,
		},
	})
}

func formatUptime(d time.Duration) string {
	d = d.Round(time.Second)
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60
	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm %ds", days, hours, minutes, seconds)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm %ds", hours, minutes, seconds)
	}
	return fmt.Sprintf("%dm %ds", minutes, seconds)
}

// buildRFC5322 constructs a minimal RFC 5322 message from a SendRequest.
func buildRFC5322(req SendRequest) []byte {
	contentType := "text/plain; charset=UTF-8"
	if req.HTML {
		contentType = "text/html; charset=UTF-8"
	}

	msgID := fmt.Sprintf("<%d.%s@smtp-server>", time.Now().UnixNano(), sanitizeDomain(req.From))
	date := time.Now().Format("Mon, 02 Jan 2006 15:04:05 -0700")

	var sb strings.Builder
	sb.WriteString("From: " + req.From + "\r\n")
	sb.WriteString("To: " + strings.Join(req.To, ", ") + "\r\n")
	sb.WriteString("Subject: " + req.Subject + "\r\n")
	sb.WriteString("Date: " + date + "\r\n")
	sb.WriteString("Message-ID: " + msgID + "\r\n")
	sb.WriteString("MIME-Version: 1.0\r\n")
	sb.WriteString("Content-Type: " + contentType + "\r\n")
	sb.WriteString("\r\n")
	sb.WriteString(req.Body)

	return []byte(sb.String())
}

// sanitizeDomain extracts the domain from an email address for use in Message-ID.
func sanitizeDomain(email string) string {
	if idx := strings.LastIndex(email, "@"); idx >= 0 {
		return email[idx+1:]
	}
	return "unknown"
}

// handleVerify verifies a single email address.
// GET  /verify?email=user@example.com
// POST /verify  {"email":"user@example.com"}
func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	var email string
	if r.Method == http.MethodGet {
		email = strings.TrimSpace(r.URL.Query().Get("email"))
	} else if r.Method == http.MethodPost {
		var body struct {
			Email string `json:"email"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		email = strings.TrimSpace(body.Email)
	} else {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "use GET or POST"})
		return
	}

	if email == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "email is required"})
		return
	}

	log.Printf("[API] verify request for %q from %s", email, r.RemoteAddr)
	result := s.verifier.Verify(email)
	writeJSON(w, http.StatusOK, result)
}

// handleVerifyBulk verifies a list of emails concurrently.
// POST /verify/bulk  {"emails":["a@b.com","c@d.com",...], "concurrency": 5}
func (s *Server) handleVerifyBulk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return
	}

	var body struct {
		Emails      []string `json:"emails"`
		Concurrency int      `json:"concurrency"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if len(body.Emails) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "emails array is required"})
		return
	}
	if len(body.Emails) > 500 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "max 500 emails per request"})
		return
	}

	concurrency := body.Concurrency
	if concurrency <= 0 {
		concurrency = 5
	}

	log.Printf("[API] bulk verify %d emails (concurrency=%d) from %s",
		len(body.Emails), concurrency, r.RemoteAddr)

	results := s.verifier.VerifyBulk(body.Emails, concurrency)

	// Build summary stats.
	valid, invalid, unknown, disposable, catchAll := 0, 0, 0, 0, 0
	for _, res := range results {
		switch {
		case res.IsDisposable:
			disposable++
		case res.IsCatchAll:
			catchAll++
			if res.Valid {
				valid++
			}
		case res.Valid:
			valid++
		case res.Checks.Mailbox == "unknown":
			unknown++
		default:
			invalid++
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"total":      len(results),
		"valid":      valid,
		"invalid":    invalid,
		"unknown":    unknown,
		"catch_all":  catchAll,
		"disposable": disposable,
		"results":    results,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
