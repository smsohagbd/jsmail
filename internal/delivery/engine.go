package delivery

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
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

// Engine delivers queued messages to remote SMTP servers.
type Engine struct {
	cfg        config.DeliveryConfig
	queue      *queue.Queue
	retryBase  time.Duration
	connectTO  time.Duration
	dkimSigner *dkim.SignOptions
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
	log.Printf("delivery: processing message id=%s from=%s to=%v attempt=%d",
		msg.ID, msg.From, msg.To, msg.RetryCount+1)

	data := msg.Data
	if e.dkimSigner != nil {
		signed, err := signDKIM(data, e.dkimSigner)
		if err != nil {
			log.Printf("delivery: DKIM sign failed for %s: %v", msg.ID, err)
		} else {
			data = signed
		}
	}

	// Group recipients by domain for efficient delivery.
	byDomain := make(map[string][]string)
	for _, rcpt := range msg.To {
		parts := strings.SplitN(rcpt, "@", 2)
		if len(parts) != 2 {
			log.Printf("delivery: skipping invalid recipient %q", rcpt)
			continue
		}
		byDomain[strings.ToLower(parts[1])] = append(byDomain[strings.ToLower(parts[1])], rcpt)
	}

	var lastErr error
	for domain, rcpts := range byDomain {
		if err := e.deliverToDomain(msg.From, domain, rcpts, data); err != nil {
			log.Printf("delivery: failed for domain=%s msg=%s: %v", domain, msg.ID, err)
			lastErr = err
		}
	}

	if lastErr == nil {
		log.Printf("delivery: message %s delivered successfully", msg.ID)
		e.queue.Complete(msg.ID)
		return
	}

	if msg.RetryCount >= e.cfg.MaxRetries {
		log.Printf("delivery: message %s permanently failed after %d retries", msg.ID, msg.RetryCount)
		e.queue.Fail(msg, fmt.Sprintf("max retries exceeded: %v", lastErr))
		return
	}

	// Exponential backoff: base * 2^attempt, capped at 24h.
	backoff := e.retryBase * (1 << uint(msg.RetryCount))
	if backoff > 24*time.Hour {
		backoff = 24 * time.Hour
	}
	log.Printf("delivery: deferring message %s for %v (attempt %d)", msg.ID, backoff, msg.RetryCount+1)
	e.queue.Defer(msg, backoff, lastErr.Error())
}

func (e *Engine) deliverToDomain(from, domain string, rcpts []string, data []byte) error {
	mxRecords, err := lookupMX(domain)
	if err != nil {
		return fmt.Errorf("MX lookup: %w", err)
	}

	for _, mx := range mxRecords {
		if err := e.sendToMX(from, mx.Host, rcpts, data); err != nil {
			log.Printf("delivery: MX %s failed: %v", mx.Host, err)
			continue
		}
		return nil
	}
	return fmt.Errorf("all MX servers failed for %s", domain)
}

func (e *Engine) sendToMX(from, mxHost string, rcpts []string, data []byte) error {
	addr := net.JoinHostPort(mxHost, "25")
	conn, err := net.DialTimeout("tcp", addr, e.connectTO)
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}

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

	if ok, _ := client.Extension("STARTTLS"); ok {
		tlsCfg := &tls.Config{
			ServerName:         mxHost,
			InsecureSkipVerify: false,
		}
		if err := client.StartTLS(tlsCfg); err != nil {
			// Non-fatal: continue without TLS if STARTTLS fails.
			log.Printf("delivery: STARTTLS to %s failed (continuing plain): %v", mxHost, err)
		}
	}

	if err := client.Mail(from); err != nil {
		return fmt.Errorf("MAIL FROM: %w", err)
	}
	for _, rcpt := range rcpts {
		if err := client.Rcpt(rcpt); err != nil {
			return fmt.Errorf("RCPT TO %s: %w", rcpt, err)
		}
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("DATA: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("write body: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("DATA close: %w", err)
	}
	return client.Quit()
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
