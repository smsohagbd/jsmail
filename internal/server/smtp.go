package server

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/emersion/go-sasl"
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

func (b *backend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	remoteIP := c.Conn().RemoteAddr().String()
	log.Printf("[SMTP] ▶ new connection from %s", remoteIP)
	return &session{backend: b, remoteIP: remoteIP}, nil
}

// session handles one SMTP connection.
type session struct {
	backend       *backend
	remoteIP      string
	authenticated bool
	authUser      string
	from          string
	to            []string
}

// AuthMechanisms tells go-smtp which auth mechanisms to advertise in EHLO.
func (s *session) AuthMechanisms() []string {
	return []string{sasl.Plain, sasl.Login}
}

// Auth returns a SASL server for the requested mechanism.
func (s *session) Auth(mech string) (sasl.Server, error) {
	switch mech {
	case sasl.Plain:
		return sasl.NewPlainServer(func(identity, username, password string) error {
			return s.checkCredentials(username, password)
		}), nil
	case sasl.Login:
		return sasl.NewLoginServer(func(username, password string) error {
			return s.checkCredentials(username, password)
		}), nil
	default:
		return nil, smtp.ErrAuthUnknownMechanism
	}
}

func (s *session) checkCredentials(username, password string) error {
	expected, ok := s.backend.users[username]
	if !ok || expected != password {
		log.Printf("[SMTP] ✗ AUTH failed       ip=%s user=%q (wrong credentials)", s.remoteIP, username)
		return errors.New("535 5.7.8 invalid credentials")
	}
	s.authenticated = true
	s.authUser = username
	log.Printf("[SMTP] ✓ AUTH ok            ip=%s user=%q", s.remoteIP, username)
	return nil
}

func (s *session) Mail(from string, _ *smtp.MailOptions) error {
	if !s.authenticated {
		log.Printf("[SMTP] ✗ MAIL FROM rejected  ip=%s from=%q (not authenticated)", s.remoteIP, from)
		return errors.New("530 5.7.0 authentication required")
	}
	s.from = from
	log.Printf("[SMTP]   MAIL FROM            ip=%s from=%q", s.remoteIP, from)
	return nil
}

func (s *session) Rcpt(to string, _ *smtp.RcptOptions) error {
	s.to = append(s.to, to)
	log.Printf("[SMTP]   RCPT TO              ip=%s to=%q", s.remoteIP, to)
	return nil
}

func (s *session) Data(r io.Reader) error {
	data, err := io.ReadAll(io.LimitReader(r, s.backend.cfg.MaxMessageSize))
	if err != nil {
		log.Printf("[SMTP] ✗ DATA read error      ip=%s err=%v", s.remoteIP, err)
		return fmt.Errorf("read data: %w", err)
	}

	log.Printf("[SMTP]   DATA received        ip=%s size=%d bytes from=%s to=%v",
		s.remoteIP, len(data), s.from, s.to)

	msg := &queue.Message{
		From: s.from,
		To:   s.to,
		Data: data,
	}
	if err := s.backend.queue.Enqueue(msg); err != nil {
		log.Printf("[SMTP] ✗ enqueue failed       ip=%s err=%v", s.remoteIP, err)
		return errors.New("451 4.3.0 failed to accept message")
	}
	log.Printf("[SMTP] ✓ message queued       ip=%s id=%s from=%s to=%v",
		s.remoteIP, msg.ID, msg.From, msg.To)
	return nil
}

func (s *session) Reset() {
	log.Printf("[SMTP]   RSET                 ip=%s", s.remoteIP)
	s.from = ""
	s.to = nil
}

func (s *session) Logout() error {
	log.Printf("[SMTP] ◀ disconnected         ip=%s user=%q", s.remoteIP, s.authUser)
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
