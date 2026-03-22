// Package smtpplain provides SMTP AUTH PLAIN on cleartext TCP.
//
// net/smtp.PlainAuth intentionally refuses non-TLS connections (except localhost)
// to avoid sending passwords in the clear. Trusted internal relays (e.g. another
// Go SMTP on :1025) still need PLAIN without TLS — use this package only in that case.
package smtpplain

import (
	"errors"
	"net/smtp"
)

// PlainAuth returns an smtp.Auth that implements PLAIN without requiring TLS.
// The host must match the server name passed to smtp.NewClient (RFC 5321 security check).
func PlainAuth(identity, username, password, host string) smtp.Auth {
	return &plainCleartext{identity: identity, username: username, password: password, host: host}
}

type plainCleartext struct {
	identity, username, password string
	host                         string
}

func (a *plainCleartext) Start(server *smtp.ServerInfo) (string, []byte, error) {
	if server.Name != a.host {
		return "", nil, errors.New("wrong host name")
	}
	resp := []byte(a.identity + "\x00" + a.username + "\x00" + a.password)
	return "PLAIN", resp, nil
}

func (a *plainCleartext) Next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		return nil, errors.New("unexpected server challenge")
	}
	return nil, nil
}
