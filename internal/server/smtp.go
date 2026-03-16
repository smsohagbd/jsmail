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

	appdb "smtp-server/internal/db"
	"smtp-server/internal/config"
	"smtp-server/internal/email"
	"smtp-server/internal/queue"
)

// UserLookup is called to authenticate a user; returns true if credentials are valid.
type UserLookup func(username, password string) bool

// backend implements smtp.Backend.
type backend struct {
	cfg             config.SMTPConfig
	queue           *queue.Queue
	users           map[string]string // fallback from config
	userLookup      UserLookup        // dynamic lookup from DB
}

func newBackend(cfg config.SMTPConfig, q *queue.Queue, lookup UserLookup) *backend {
	users := make(map[string]string)
	for _, u := range cfg.Auth.Users {
		users[u.Username] = u.Password
	}
	return &backend{cfg: cfg, queue: q, users: users, userLookup: lookup}
}

func (b *backend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	remoteIP := c.Conn().RemoteAddr().String()
	if b.cfg.VerboseLog {
		log.Printf("[SMTP] ▶ new connection from %s", remoteIP)
	}
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
	ok := false

	// Prefer DB lookup if available
	if s.backend.userLookup != nil {
		ok = s.backend.userLookup(username, password)
	}
	// Fall back to config users
	if !ok {
		expected, found := s.backend.users[username]
		ok = found && expected == password
	}

	if !ok {
		log.Printf("[SMTP] ✗ AUTH failed       ip=%s user=%q (wrong credentials)", s.remoteIP, username)
		return errors.New("535 5.7.8 invalid credentials")
	}
	s.authenticated = true
	s.authUser = username
	if s.backend.cfg.VerboseLog {
		log.Printf("[SMTP] ✓ AUTH ok            ip=%s user=%q", s.remoteIP, username)
	}
	return nil
}

func (s *session) Mail(from string, _ *smtp.MailOptions) error {
	if !s.authenticated {
		log.Printf("[SMTP] ✗ MAIL FROM rejected  ip=%s from=%q (not authenticated)", s.remoteIP, from)
		return errors.New("530 5.7.0 authentication required")
	}
	s.from = from
	if s.backend.cfg.VerboseLog {
		log.Printf("[SMTP]   MAIL FROM            ip=%s from=%q", s.remoteIP, from)
	}
	return nil
}

func (s *session) Rcpt(to string, _ *smtp.RcptOptions) error {
	if appdb.IsHardBounced(to) {
		log.Printf("[SMTP] ✗ RCPT TO rejected     ip=%s to=%q (hard bounce suppressed)", s.remoteIP, to)
		return errors.New("550 5.1.1 address rejected — permanently bounced")
	}
	s.to = append(s.to, to)
	if s.backend.cfg.VerboseLog {
		log.Printf("[SMTP]   RCPT TO              ip=%s to=%q", s.remoteIP, to)
	}
	return nil
}

func (s *session) Data(r io.Reader) error {
	data, err := io.ReadAll(io.LimitReader(r, s.backend.cfg.MaxMessageSize))
	if err != nil {
		log.Printf("[SMTP] ✗ DATA read error      ip=%s err=%v", s.remoteIP, err)
		return fmt.Errorf("read data: %w", err)
	}

	if s.backend.cfg.VerboseLog {
		log.Printf("[SMTP]   DATA received        ip=%s size=%d bytes from=%s to=%v",
			s.remoteIP, len(data), s.from, s.to)
	}

	from := s.from
	// Force Email From / Force From / Templates: each has its own enable. Force Email address takes precedence over Force From.
	if appdb.GetForceEmailEnabled() || appdb.GetForceFromEnabled() || len(appdb.GetForceEmailTemplates()) > 0 {
		newFrom, subj, body, applied := appdb.GetNextForceEmail(from)
		if applied {
			if newFrom != from {
				from = newFrom
				data = email.RewriteFromHeader(data, from)
			}
			if subj != "" || body != "" {
				mappings := appdb.GetLinkTrackingMappings()
				linkMappings := make([]email.LinkMapping, len(mappings))
				for i, m := range mappings {
					linkMappings[i] = email.LinkMapping{URL: m.URL, TrackingID: m.TrackingID}
				}
				redirectBase := appdb.GetLinkTrackingRedirectBase()
				data = email.RewriteSubjectAndBody(data, subj, body, linkMappings, redirectBase)
			}
			if s.backend.cfg.VerboseLog {
				log.Printf("[SMTP]   force applied  ip=%s from=%s subj=%q", s.remoteIP, from, subj)
			}
		}
	}

	msg := &queue.Message{
		Username: s.authUser,
		From:     from,
		To:       s.to,
		Data:     data,
	}
	if err := s.backend.queue.Enqueue(msg); err != nil {
		log.Printf("[SMTP] ✗ enqueue failed       ip=%s err=%v", s.remoteIP, err)
		return errors.New("451 4.3.0 failed to accept message")
	}
	// Log to DB if available
	appdb.LogQueued(s.authUser, msg.ID, msg.From, msg.To)
	if s.backend.cfg.VerboseLog {
		log.Printf("[SMTP] ✓ message queued       ip=%s id=%s from=%s to=%v",
			s.remoteIP, msg.ID, msg.From, msg.To)
	}
	return nil
}

func (s *session) Reset() {
	if s.backend.cfg.VerboseLog {
		log.Printf("[SMTP]   RSET                 ip=%s", s.remoteIP)
	}
	s.from = ""
	s.to = nil
}

func (s *session) Logout() error {
	if s.backend.cfg.VerboseLog {
		log.Printf("[SMTP] ◀ disconnected         ip=%s user=%q", s.remoteIP, s.authUser)
	}
	return nil
}

// Start launches the SMTP server and blocks until it fails.
// Supports two TLS modes:
//   - "starttls"  (default) — plain SMTP on the port, STARTTLS upgrade available (RFC 3207)
//   - "implicit"            — SSL/TLS wraps the connection from the first byte (SMTPS, port 465)
func Start(cfg config.SMTPConfig, q *queue.Queue) error {
	lookup := func(username, password string) bool {
		_, ok := appdb.CheckPassword(username, password)
		return ok
	}
	b := newBackend(cfg, q, lookup)

	srv := smtp.NewServer(b)
	srv.Addr = cfg.ListenAddr
	srv.Domain = cfg.Domain
	srv.WriteTimeout = 30 * time.Second
	srv.ReadTimeout = 60 * time.Second
	srv.MaxMessageBytes = cfg.MaxMessageSize
	srv.MaxRecipients = 50
	// Always allow auth — the server already requires authentication for every
	// submission regardless of whether the transport is encrypted. Clients on
	// non-standard ports (e.g. 1069) that cannot do STARTTLS must still be able
	// to authenticate so they can submit mail.
	srv.AllowInsecureAuth = true

	tlsMode := cfg.TLS.Mode
	if tlsMode == "" {
		tlsMode = "starttls"
	}

	if cfg.TLS.Enabled {
		cert, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		if err != nil {
			return fmt.Errorf("load TLS certificate (%s): %w", cfg.TLS.CertFile, err)
		}
		tlsCfg := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}

		switch tlsMode {
		case "implicit":
			// SMTPS — TLS wraps the whole connection (like port 465).
			// Clients must connect with SSL/TLS enabled from the start.
			srv.TLSConfig = tlsCfg
			log.Printf("server: SMTP listening on %s (domain=%s, mode=implicit-TLS)", cfg.ListenAddr, cfg.Domain)
			return srv.ListenAndServeTLS()
		default: // "starttls"
			// Plain SMTP that advertises STARTTLS; clients upgrade inside the session.
			srv.TLSConfig = tlsCfg
			log.Printf("server: SMTP listening on %s (domain=%s, mode=STARTTLS)", cfg.ListenAddr, cfg.Domain)
			return srv.ListenAndServe()
		}
	}

	log.Printf("server: SMTP listening on %s (domain=%s, tls=disabled)", cfg.ListenAddr, cfg.Domain)
	return srv.ListenAndServe()
}
