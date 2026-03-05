package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"smtp-server/internal/config"
	"smtp-server/internal/queue"
)

// Server exposes an HTTP API for injecting messages into the queue.
type Server struct {
	cfg   config.APIConfig
	queue *queue.Queue
}

func New(cfg config.APIConfig, q *queue.Queue) *Server {
	return &Server{cfg: cfg, queue: q}
}

func (s *Server) Start() {
	mux := http.NewServeMux()
	mux.HandleFunc("/send", s.requireAuth(s.handleSend))
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

	msg := &queue.Message{
		From: req.From,
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
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
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

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
