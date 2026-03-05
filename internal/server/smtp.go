package server

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/emersion/go-smtp"

	"smtp-server/internal/config"
	"smtp-server/internal/queue"
)

// backend implements smtp.Backend.
type backend struct {
	cfg   config.SMTPConfig
	queue *queue.Queue
	users map[string]string
}

func newBackend(cfg config.SMTPConfig, q *queue.Queue) *backend {
	users := make(map[string]string)
	for _, u := range cfg.Auth.Users {
		users[u.Username] = u.Password
	}
	return &backend{cfg: cfg, queue: q, users: users}
}

func (b *backend) NewSession(_ *smtp.Conn) (smtp.Session, error) {
	return &session{backend: b}, nil
}

// session handles one SMTP connection.
type session struct {
	backend       *backend
	authenticated bool
	from          string
	to            []string
}

func (s *session) AuthPlain(username, password string) error {
	expected, ok := s.backend.users[username]
	if !ok || expected != password {
		return errors.New("invalid credentials")
	}
	s.authenticated = true
	return nil
}

func (s *session) Mail(from string, _ *smtp.MailOptions) error {
	if !s.authenticated {
		return errors.New("530 5.7.0 authentication required")
	}
	s.from = from
	return nil
}

func (s *session) Rcpt(to string, _ *smtp.RcptOptions) error {
	s.to = append(s.to, to)
	return nil
}

func (s *session) Data(r io.Reader) error {
	data, err := io.ReadAll(io.LimitReader(r, s.backend.cfg.MaxMessageSize))
	if err != nil {
		return fmt.Errorf("read data: %w", err)
	}

	msg := &queue.Message{
		From: s.from,
		To:   s.to,
		Data: data,
	}
	if err := s.backend.queue.Enqueue(msg); err != nil {
		log.Printf("server: failed to enqueue message: %v", err)
		return errors.New("451 4.3.0 failed to accept message")
	}
	log.Printf("server: accepted message %s from=%s to=%v", msg.ID, msg.From, msg.To)
	return nil
}

func (s *session) Reset() {
	s.from = ""
	s.to = nil
}

func (s *session) Logout() error {
	return nil
}

// Start launches the SMTP server and blocks until it fails.
func Start(cfg config.SMTPConfig, q *queue.Queue) error {
	b := newBackend(cfg, q)

	srv := smtp.NewServer(b)
	srv.Addr = cfg.ListenAddr
	srv.Domain = cfg.Domain
	srv.WriteTimeout = 30 * time.Second
	srv.ReadTimeout = 60 * time.Second
	srv.MaxMessageBytes = cfg.MaxMessageSize
	srv.MaxRecipients = 50
	srv.AllowInsecureAuth = !cfg.TLS.Enabled

	if cfg.TLS.Enabled {
		cert, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		if err != nil {
			return fmt.Errorf("load TLS certificate: %w", err)
		}
		srv.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
	}

	log.Printf("server: SMTP listening on %s (domain=%s, tls=%v)", cfg.ListenAddr, cfg.Domain, cfg.TLS.Enabled)
	return srv.ListenAndServe()
}
