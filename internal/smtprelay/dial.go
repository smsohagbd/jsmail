// Package smtprelay dials user-configured SMTP relays with TLS modes including
// port-based auto detection and optional cleartext PLAIN auth.
package smtprelay

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"

	"smtp-server/internal/smtpplain"
)

// Logf optional verbose logging (e.g. delivery engine).
type Logf func(format string, args ...interface{})

// Config for establishing an authenticated SMTP client.
type Config struct {
	Host     string
	Port     int
	Username string
	Password string
	// TLSMode: auto | starttls | ssl | none | "" (same as auto)
	TLSMode string
	// DialTimeout for TCP/TLS dial
	DialTimeout time.Duration
	// Helo name sent after connect
	Helo string
	// Logf optional; nil disables
	Logf Logf
	// MinTLSVersion for TLS (0 = TLS 1.2)
	MinTLSVersion uint16
}

// EffectiveTLSMode maps auto/empty + port to a concrete dial strategy.
// starttls = plain TCP then STARTTLS (required when offered for starttls mode).
// negotiate = plain TCP, upgrade with STARTTLS if advertised (optional upgrade).
// ssl = implicit TLS from first byte.
// none = plain only, no STARTTLS.
func EffectiveTLSMode(port int, mode string) string {
	m := strings.ToLower(strings.TrimSpace(mode))
	if m == "" || m == "auto" {
		switch port {
		case 465:
			return "ssl"
		case 587:
			return "starttls"
		default:
			return "negotiate"
		}
	}
	return m
}

// DialAndAuthenticate connects, negotiates TLS per mode, and runs AUTH if credentials are set.
// Caller must Close() the client and send mail / Quit.
func DialAndAuthenticate(cfg Config) (*smtp.Client, error) {
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 10 * time.Second
	}
	if cfg.Helo == "" {
		cfg.Helo = "localhost"
	}
	minV := cfg.MinTLSVersion
	if minV == 0 {
		minV = tls.VersionTLS12
	}

	mode := EffectiveTLSMode(cfg.Port, cfg.TLSMode)
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	logf := cfg.Logf
	if logf == nil {
		logf = func(string, ...interface{}) {}
	}

	var conn net.Conn
	var err error
	tlsActive := false

	switch mode {
	case "ssl":
		tlsCfg := &tls.Config{ServerName: cfg.Host, MinVersion: minV}
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: cfg.DialTimeout}, "tcp4", addr, tlsCfg)
		if err != nil {
			return nil, fmt.Errorf("TLS connect %s: %w", addr, err)
		}
		tlsActive = true
		logf("relay TLS connected to %s", addr)
	case "starttls", "negotiate", "none":
		conn, err = net.DialTimeout("tcp4", addr, cfg.DialTimeout)
		if err != nil {
			return nil, fmt.Errorf("connect %s: %w", addr, err)
		}
		logf("relay TCP connected to %s", addr)
	default:
		return nil, fmt.Errorf("unknown TLS mode %q", mode)
	}
	// Note: conn closed by client.Close() in callers that defer client.Close()

	client, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("SMTP handshake: %w", err)
	}

	if err := client.Hello(cfg.Helo); err != nil {
		client.Close()
		return nil, fmt.Errorf("EHLO: %w", err)
	}

	switch mode {
	case "starttls":
		if ok, _ := client.Extension("STARTTLS"); ok {
			tlsCfg := &tls.Config{ServerName: cfg.Host, MinVersion: minV}
			if err := client.StartTLS(tlsCfg); err != nil {
				client.Close()
				return nil, fmt.Errorf("STARTTLS: %w", err)
			}
			tlsActive = true
			logf("relay STARTTLS ok")
		} else if cfg.Username != "" {
			client.Close()
			return nil, fmt.Errorf("server does not offer STARTTLS; use SSL, None, or a port that matches your server (e.g. 465 for implicit TLS)")
		}
	case "negotiate":
		if ok, _ := client.Extension("STARTTLS"); ok {
			tlsCfg := &tls.Config{ServerName: cfg.Host, MinVersion: minV}
			if err := client.StartTLS(tlsCfg); err != nil {
				logf("relay STARTTLS optional upgrade failed (%v), continuing plain", err)
			} else {
				tlsActive = true
				logf("relay STARTTLS ok (negotiated)")
			}
		}
	case "none", "ssl":
		// none: no upgrade; ssl: already TLS
	}

	if cfg.Username != "" {
		var auth smtp.Auth
		if tlsActive {
			auth = smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
		} else {
			auth = smtpplain.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
		}
		if err := client.Auth(auth); err != nil {
			client.Close()
			return nil, fmt.Errorf("AUTH: %w", err)
		}
		logf("relay AUTH ok (user=%s)", cfg.Username)
	}

	return client, nil
}
