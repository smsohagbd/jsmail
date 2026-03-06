package delivery

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"net/smtp"
	"os"
	"strings"
	"time"

	"github.com/emersion/go-msgauth/dkim"

	"smtp-server/internal/config"
	"smtp-server/internal/queue"
)

// DeliveryEvent carries the result of a delivery attempt for a single recipient.
type DeliveryEvent struct {
	MessageID string
	Username  string
	From      string
	To        string
	Status    string // delivered | failed | deferred
	Error     string
	MXHost    string
}

// Engine delivers queued messages to remote SMTP servers.
type Engine struct {
	cfg        config.DeliveryConfig
	queue      *queue.Queue
	retryBase  time.Duration
	connectTO  time.Duration
	dkimSigner *dkim.SignOptions
	OnEvent    func(DeliveryEvent) // optional hook for DB logging
}

// New creates a delivery Engine.
func New(cfg config.DeliveryConfig, q *queue.Queue) *Engine {
	e := &Engine{cfg: cfg, queue: q}

	if d, err := time.ParseDuration(cfg.RetryInterval); err == nil {
		e.retryBase = d
	} else {
		e.retryBase = 5 * time.Minute
	}
	if d, err := time.ParseDuration(cfg.ConnectTimeout); err == nil {
		e.connectTO = d
	} else {
		e.connectTO = 30 * time.Second
	}

	if cfg.DKIM.Enabled {
		if opts, err := loadDKIMSigner(cfg.DKIM); err != nil {
			log.Printf("delivery: DKIM disabled — failed to load key: %v", err)
		} else {
			e.dkimSigner = opts
			log.Printf("delivery: DKIM enabled for domain=%s selector=%s", cfg.DKIM.Domain, cfg.DKIM.Selector)
		}
	}

	return e
}

// Start launches worker goroutines and returns immediately.
func (e *Engine) Start() {
	log.Printf("delivery: starting %d workers", e.cfg.Workers)
	for i := 0; i < e.cfg.Workers; i++ {
		go e.worker(i)
	}
}

func (e *Engine) worker(id int) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-e.queue.Ready():
		case <-ticker.C:
		}
		for {
			msg := e.queue.Pop()
			if msg == nil {
				break
			}
			e.deliver(msg)
		}
	}
}

func (e *Engine) deliver(msg *queue.Message) {
	log.Printf("[DELIVERY] ══════════════════════════════════════════")
	log.Printf("[DELIVERY]   id      = %s", msg.ID)
	log.Printf("[DELIVERY]   from    = %s", msg.From)
	log.Printf("[DELIVERY]   to      = %v", msg.To)
	log.Printf("[DELIVERY]   attempt = %d / %d", msg.RetryCount+1, e.cfg.MaxRetries+1)
	log.Printf("[DELIVERY]   size    = %d bytes", len(msg.Data))

	data := injectMissingHeaders(msg.Data, e.cfg.HeloName)
	if e.dkimSigner != nil {
		signed, err := signDKIM(data, e.dkimSigner)
		if err != nil {
			log.Printf("[DELIVERY] ⚠ DKIM sign failed (sending unsigned): %v", err)
		} else {
			data = signed
			log.Printf("[DELIVERY]   DKIM signed ok")
		}
	}

	// Group recipients by domain for efficient delivery.
	byDomain := make(map[string][]string)
	for _, rcpt := range msg.To {
		parts := strings.SplitN(rcpt, "@", 2)
		if len(parts) != 2 {
			log.Printf("[DELIVERY] ⚠ skipping invalid recipient %q", rcpt)
			continue
		}
		domain := strings.ToLower(parts[1])
		byDomain[domain] = append(byDomain[domain], rcpt)
	}

	var lastErr error
	// recipientMX tracks which MX host delivered each recipient.
	recipientMX := make(map[string]string)

	for domain, rcpts := range byDomain {
		log.Printf("[DELIVERY]   delivering to domain %q (%v)", domain, rcpts)
		mxHost, err := e.deliverToDomain(msg.From, domain, rcpts, data)
		if err != nil {
			log.Printf("[DELIVERY] ✗ domain %q failed: %v", domain, err)
			if isPermanentSMTPError(err) {
				// Hard bounce — emit event per recipient, do NOT set lastErr (skip retry)
				log.Printf("[DELIVERY] ✗ hard bounce detected for domain %q", domain)
				if e.OnEvent != nil {
					for _, rcpt := range rcpts {
						e.OnEvent(DeliveryEvent{
							MessageID: msg.ID, Username: msg.Username,
							From: msg.From, To: rcpt, Status: "hard_bounce",
							Error: err.Error(),
						})
					}
				}
			} else {
				lastErr = err
			}
		} else {
			for _, rcpt := range rcpts {
				recipientMX[rcpt] = mxHost
			}
		}
	}

	if lastErr == nil {
		log.Printf("[DELIVERY] ✓ message %s DELIVERED SUCCESSFULLY", msg.ID)
		e.queue.Complete(msg.ID)
		if e.OnEvent != nil {
			for _, to := range msg.To {
				e.OnEvent(DeliveryEvent{
					MessageID: msg.ID, Username: msg.Username,
					From: msg.From, To: to, Status: "delivered",
					MXHost: recipientMX[to],
				})
			}
		}
		return
	}

	if msg.RetryCount >= e.cfg.MaxRetries {
		log.Printf("[DELIVERY] ✗ message %s PERMANENTLY FAILED (max retries reached)", msg.ID)
		log.Printf("[DELIVERY]   reason: %v", lastErr)
		e.queue.Fail(msg, fmt.Sprintf("max retries exceeded: %v", lastErr))
		if e.OnEvent != nil {
			for _, to := range msg.To {
				e.OnEvent(DeliveryEvent{
					MessageID: msg.ID, Username: msg.Username,
					From: msg.From, To: to, Status: "failed",
					Error: lastErr.Error(),
				})
			}
		}
		return
	}

	// Exponential backoff: base * 2^attempt, capped at 24h.
	backoff := e.retryBase * (1 << uint(msg.RetryCount))
	if backoff > 24*time.Hour {
		backoff = 24 * time.Hour
	}
	log.Printf("[DELIVERY] ⏳ message %s DEFERRED — retry in %v (attempt %d next)",
		msg.ID, backoff, msg.RetryCount+2)
	log.Printf("[DELIVERY]   reason: %v", lastErr)
	e.queue.Defer(msg, backoff, lastErr.Error())
	if e.OnEvent != nil {
		for _, to := range msg.To {
			e.OnEvent(DeliveryEvent{
				MessageID: msg.ID, Username: msg.Username,
				From: msg.From, To: to, Status: "deferred",
				Error: lastErr.Error(),
			})
		}
	}
}

// deliveryPorts defines the ports tried in order for outbound delivery.
// Port 25 is the standard MTA port; 587 is tried as fallback when 25 is blocked.
var deliveryPorts = []string{"25", "587"}

// deliverToDomain attempts delivery to a domain, returning the successful MX host on success.
func (e *Engine) deliverToDomain(from, domain string, rcpts []string, data []byte) (string, error) {
	log.Printf("[DELIVERY]   DNS MX lookup for %q", domain)
	mxRecords, err := lookupMX(domain)
	if err != nil {
		log.Printf("[DELIVERY] ✗ MX lookup failed for %q: %v", domain, err)
		return "", fmt.Errorf("MX lookup: %w", err)
	}

	log.Printf("[DELIVERY]   MX records for %q:", domain)
	for _, mx := range mxRecords {
		log.Printf("[DELIVERY]     pref=%d  host=%s", mx.Pref, mx.Host)
	}

	for _, mx := range mxRecords {
		for _, port := range deliveryPorts {
			log.Printf("[DELIVERY]   trying MX %s port=%s (pref=%d)", mx.Host, port, mx.Pref)
			if err := e.sendToMX(from, mx.Host, port, rcpts, data); err != nil {
				log.Printf("[DELIVERY] ✗ MX %s:%s failed: %v", mx.Host, port, err)
				continue
			}
			log.Printf("[DELIVERY] ✓ delivered via MX %s:%s", mx.Host, port)
			return mx.Host, nil
		}
	}
	return "", fmt.Errorf("all MX servers failed for %s", domain)
}

func (e *Engine) sendToMX(from, mxHost, port string, rcpts []string, data []byte) error {
	addr := net.JoinHostPort(mxHost, port)
	log.Printf("[DELIVERY]   connecting to %s …", addr)

	conn, err := net.DialTimeout("tcp", addr, e.connectTO)
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	log.Printf("[DELIVERY]   TCP connected to %s", addr)

	heloName := e.cfg.HeloName
	if heloName == "" {
		heloName = "localhost"
	}

	client, err := smtp.NewClient(conn, mxHost)
	if err != nil {
		conn.Close()
		return fmt.Errorf("new client: %w", err)
	}
	defer client.Close()

	if err := client.Hello(heloName); err != nil {
		return fmt.Errorf("EHLO: %w", err)
	}
	log.Printf("[DELIVERY]   EHLO %s → ok", heloName)

	if ok, _ := client.Extension("STARTTLS"); ok {
		log.Printf("[DELIVERY]   STARTTLS supported, upgrading …")
		tlsCfg := &tls.Config{
			ServerName:         mxHost,
			InsecureSkipVerify: false,
		}
		if err := client.StartTLS(tlsCfg); err != nil {
			log.Printf("[DELIVERY] ⚠ STARTTLS failed (continuing plain): %v", err)
		} else {
			log.Printf("[DELIVERY]   STARTTLS ok (TLS active)")
		}
	} else {
		log.Printf("[DELIVERY]   STARTTLS not supported, sending plain")
	}

	if err := client.Mail(from); err != nil {
		return fmt.Errorf("MAIL FROM <%s>: %w", from, err)
	}
	log.Printf("[DELIVERY]   MAIL FROM <%s> → ok", from)

	for _, rcpt := range rcpts {
		if err := client.Rcpt(rcpt); err != nil {
			return fmt.Errorf("RCPT TO <%s>: %w", rcpt, err)
		}
		log.Printf("[DELIVERY]   RCPT TO <%s> → ok", rcpt)
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("DATA: %w", err)
	}
	n, err := w.Write(data)
	if err != nil {
		return fmt.Errorf("write body: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("DATA close: %w", err)
	}
	log.Printf("[DELIVERY]   DATA sent (%d bytes) → ok", n)

	if err := client.Quit(); err != nil {
		log.Printf("[DELIVERY] ⚠ QUIT error (message was accepted): %v", err)
	}
	return nil
}

// ---- Header injection ----

// injectMissingHeaders ensures the message has the required RFC 5322 headers
// (Message-ID and Date) that Gmail and other providers reject without.
func injectMissingHeaders(data []byte, domain string) []byte {
	header, body, found := bytes.Cut(data, []byte("\r\n\r\n"))
	if !found {
		// Try Unix line endings
		header, body, found = bytes.Cut(data, []byte("\n\n"))
		if !found {
			return data
		}
	}

	headerStr := string(header)
	var inject strings.Builder

	if !containsHeader(headerStr, "Message-ID") {
		b := make([]byte, 12)
		rand.Read(b)
		msgID := fmt.Sprintf("Message-ID: <%d.%s@%s>\r\n",
			time.Now().UnixNano(), hex.EncodeToString(b), domain)
		inject.WriteString(msgID)
		log.Printf("[DELIVERY]   injected Message-ID header")
	}

	if !containsHeader(headerStr, "Date") {
		inject.WriteString("Date: " + time.Now().Format("Mon, 02 Jan 2006 15:04:05 -0700") + "\r\n")
		log.Printf("[DELIVERY]   injected Date header")
	}

	if inject.Len() == 0 {
		return data
	}

	sep := "\r\n\r\n"
	if !found {
		sep = "\n\n"
	}
	return []byte(inject.String() + headerStr + sep + string(body))
}

func containsHeader(header, name string) bool {
	lower := strings.ToLower(header)
	return strings.Contains(lower, "\n"+strings.ToLower(name)+":") ||
		strings.HasPrefix(lower, strings.ToLower(name)+":")
}

// ---- DKIM helpers ----

func loadDKIMSigner(cfg config.DKIMConfig) (*dkim.SignOptions, error) {
	keyData, err := os.ReadFile(cfg.PrivateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM data in %s", cfg.PrivateKeyFile)
	}

	var privateKey *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS1 key: %w", err)
		}
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS8 key: %w", err)
		}
		var ok bool
		privateKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("DKIM only supports RSA keys")
		}
	default:
		return nil, fmt.Errorf("unsupported PEM block type: %s", block.Type)
	}

	return &dkim.SignOptions{
		Domain:   cfg.Domain,
		Selector: cfg.Selector,
		Signer:   privateKey,
		HeaderKeys: []string{
			"From", "To", "Subject", "Date", "Message-ID", "Content-Type",
		},
	}, nil
}

func signDKIM(data []byte, opts *dkim.SignOptions) ([]byte, error) {
	var buf bytes.Buffer
	if err := dkim.Sign(&buf, bytes.NewReader(data), opts); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// isPermanentSMTPError returns true if the error represents a 5xx permanent
// SMTP rejection (hard bounce). 4xx errors are temporary (soft bounce).
func isPermanentSMTPError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	lower := strings.ToLower(msg)
	// Check for explicit 5xx SMTP codes in the error string.
	for _, code := range []string{
		"550 ", "550:", "551 ", "551:", "552 ", "552:",
		"553 ", "553:", "554 ", "554:", "521 ", "521:",
	} {
		if strings.Contains(msg, code) {
			return true
		}
	}
	// Keyword fallback.
	return strings.Contains(lower, "mailbox not found") ||
		strings.Contains(lower, "no such user") ||
		strings.Contains(lower, "user unknown") ||
		strings.Contains(lower, "does not exist") ||
		strings.Contains(lower, "bad destination") ||
		strings.Contains(lower, "invalid recipient") ||
		strings.Contains(lower, "address rejected")
}
