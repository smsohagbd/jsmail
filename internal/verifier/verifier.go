package verifier

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/smtp"
	"regexp"
	"strings"
	"time"
)

// Status values returned per check.
const (
	StatusPass    = "pass"
	StatusFail    = "fail"
	StatusUnknown = "unknown" // server blocked the probe / grey-listed
)

// Result is the full verification report for one email address.
type Result struct {
	Email        string  `json:"email"`
	Valid         bool    `json:"valid"`
	Reason       string  `json:"reason,omitempty"`
	IsCatchAll   bool    `json:"is_catch_all"`
	IsDisposable bool    `json:"is_disposable"`
	MXHost       string  `json:"mx_host,omitempty"`
	Checks       Checks  `json:"checks"`
	VerifiedAt   string  `json:"verified_at"`
}

// Checks holds the individual check results.
type Checks struct {
	Format      string `json:"format"`       // pass / fail
	MXExists    string `json:"mx_exists"`    // pass / fail
	SMTPConnect string `json:"smtp_connect"` // pass / fail / unknown
	Mailbox     string `json:"mailbox"`      // pass / fail / unknown
}

// Config controls the verifier behaviour.
type Config struct {
	// HeloName is the domain used in EHLO and MAIL FROM during the probe.
	HeloName       string
	ConnectTimeout time.Duration
	// ProbeFrom is the sender address used in the MAIL FROM probe.
	// Defaults to verify@<HeloName>.
	ProbeFrom string
}

// Verifier performs email address verification.
type Verifier struct {
	cfg Config
}

// New creates a Verifier with the given config.
func New(cfg Config) *Verifier {
	if cfg.ConnectTimeout == 0 {
		cfg.ConnectTimeout = 10 * time.Second
	}
	if cfg.HeloName == "" {
		cfg.HeloName = "localhost"
	}
	if cfg.ProbeFrom == "" {
		cfg.ProbeFrom = "verify@" + cfg.HeloName
	}
	return &Verifier{cfg: cfg}
}

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

// Verify runs all checks on a single email address.
func (v *Verifier) Verify(email string) Result {
	email = strings.TrimSpace(strings.ToLower(email))
	r := Result{
		Email:      email,
		VerifiedAt: time.Now().UTC().Format(time.RFC3339),
	}

	// ── 1. Format check ──────────────────────────────────────────────────────
	if !emailRegex.MatchString(email) {
		r.Checks.Format = StatusFail
		r.Checks.MXExists = StatusUnknown
		r.Checks.SMTPConnect = StatusUnknown
		r.Checks.Mailbox = StatusUnknown
		r.Valid = false
		r.Reason = "invalid email format"
		return r
	}
	r.Checks.Format = StatusPass

	parts := strings.SplitN(email, "@", 2)
	domain := parts[1]

	// ── 2. Disposable domain check ───────────────────────────────────────────
	r.IsDisposable = isDisposable(domain)

	// ── 3. MX lookup ─────────────────────────────────────────────────────────
	mxRecords, err := net.LookupMX(domain)
	if err != nil || len(mxRecords) == 0 {
		r.Checks.MXExists = StatusFail
		r.Checks.SMTPConnect = StatusUnknown
		r.Checks.Mailbox = StatusUnknown
		r.Valid = false
		r.Reason = "no MX records found for domain " + domain
		return r
	}
	r.Checks.MXExists = StatusPass

	// Sort by preference (lowest = highest priority)
	mxHost := strings.TrimSuffix(mxRecords[0].Host, ".")
	for _, mx := range mxRecords {
		if mx.Pref < mxRecords[0].Pref {
			mxHost = strings.TrimSuffix(mx.Host, ".")
		}
	}
	r.MXHost = mxHost

	// ── 4. SMTP handshake probe ───────────────────────────────────────────────
	// Connect directly to the recipient's MX server and perform the SMTP handshake:
	//   EHLO → MAIL FROM → RCPT TO → (abort, no DATA sent)
	//
	// Rule: 250 on RCPT TO = valid, forward to relay.
	//       Any error at any step = abort, do not forward.
	//
	// This mirrors exactly what direct MX delivery does, but stops before DATA.
	// For providers that use DHA (Yahoo/AOL from untrusted IPs) and return 250
	// for every RCPT TO: the address passes here and the relay does the real
	// delivery. The relay's IP may be trusted by Yahoo, so it will get the actual
	// 552/250 response at DATA close — recorded as hard_bounce or delivered.
	smtpResult, serverDetail := v.smtpProbe(email, mxHost)
	r.IsCatchAll = false

	switch smtpResult {
	case probeExists:
		r.Checks.SMTPConnect = StatusPass
		r.Checks.Mailbox = StatusPass
		r.Valid = true
	case probeNotFound:
		r.Checks.SMTPConnect = StatusPass
		r.Checks.Mailbox = StatusFail
		r.Valid = false
		r.Reason = fmt.Sprintf("mailbox does not exist [server: %s]", serverDetail)
	case probeConnectFail:
		r.Checks.SMTPConnect = StatusFail
		r.Checks.Mailbox = StatusUnknown
		r.Valid = false
		r.Reason = fmt.Sprintf("could not connect to mail server [%s]", serverDetail)
	case probeUnknown:
		r.Checks.SMTPConnect = StatusPass
		r.Checks.Mailbox = StatusUnknown
		r.Valid = false
		r.Reason = fmt.Sprintf("server rejected handshake — cannot verify mailbox [server: %s]", serverDetail)
	}

	log.Printf("[VERIFY] %s → valid=%v reason=%q mx=%s catch_all=%v disposable=%v",
		email, r.Valid, r.Reason, r.MXHost, r.IsCatchAll, r.IsDisposable)

	return r
}

// VerifyBulk verifies a list of email addresses concurrently.
// maxConcurrency limits parallel SMTP connections.
func (v *Verifier) VerifyBulk(emails []string, maxConcurrency int) []Result {
	if maxConcurrency <= 0 {
		maxConcurrency = 5
	}

	results := make([]Result, len(emails))
	sem := make(chan struct{}, maxConcurrency)

	type indexedResult struct {
		idx int
		res Result
	}
	out := make(chan indexedResult, len(emails))

	for i, email := range emails {
		sem <- struct{}{}
		go func(idx int, e string) {
			defer func() { <-sem }()
			out <- indexedResult{idx: idx, res: v.Verify(e)}
		}(i, email)
	}

	for range emails {
		ir := <-out
		results[ir.idx] = ir.res
	}
	return results
}

// ── SMTP probe internals ──────────────────────────────────────────────────────

type probeResult int

const (
	probeExists      probeResult = iota // 250 RCPT TO accepted
	probeNotFound                       // 550/551/552/553 mailbox unknown
	probeConnectFail                    // TCP / EHLO failed
	probeUnknown                        // server refused to tell us
)

// smtpProbe connects to mxHost and performs the SMTP handshake up to RCPT TO.
// It aborts before sending any DATA — no email is ever transmitted.
// Returns (result, raw-server-detail).
func (v *Verifier) smtpProbe(email, mxHost string) (probeResult, string) {
	conn, err := net.DialTimeout("tcp4", net.JoinHostPort(mxHost, "25"), v.cfg.ConnectTimeout)
	if err != nil {
		conn, err = net.DialTimeout("tcp4", net.JoinHostPort(mxHost, "587"), v.cfg.ConnectTimeout)
		if err != nil {
			return probeConnectFail, fmt.Sprintf("TCP connect failed: %v", err)
		}
	}

	client, err := smtp.NewClient(conn, mxHost)
	if err != nil {
		conn.Close()
		return probeConnectFail, fmt.Sprintf("SMTP handshake failed: %v", err)
	}
	defer client.Close()

	if err := client.Hello(v.cfg.HeloName); err != nil {
		return probeConnectFail, fmt.Sprintf("EHLO rejected: %v", err)
	}

	if ok, _ := client.Extension("STARTTLS"); ok {
		tlsCfg := &tls.Config{ServerName: mxHost, InsecureSkipVerify: false}
		client.StartTLS(tlsCfg) // non-fatal if fails
	}

	if err := client.Mail(v.cfg.ProbeFrom); err != nil {
		return probeUnknown, fmt.Sprintf("MAIL FROM rejected by %s: %v", mxHost, err)
	}

	// RCPT TO — the decisive step. 250 = address accepted. Any error = abort.
	return rcptProbe(client, email)
}

// rcptProbe issues RCPT TO and returns (result, raw-server-detail).
func rcptProbe(client *smtp.Client, addr string) (probeResult, string) {
	err := client.Rcpt(addr)
	if err == nil {
		return probeExists, "250 OK"
	}
	raw := err.Error()
	msg := strings.ToLower(raw)
	// Permanent 5xx rejections = mailbox not found.
	if strings.HasPrefix(raw, "55") ||
		strings.Contains(msg, "no such user") ||
		strings.Contains(msg, "user unknown") ||
		strings.Contains(msg, "does not exist") ||
		strings.Contains(msg, "invalid address") ||
		strings.Contains(msg, "mailbox not found") ||
		strings.Contains(msg, "not a valid recipient") ||
		strings.Contains(msg, "doesn't have a yahoo.com account") ||
		strings.Contains(msg, "bad destination") {
		return probeNotFound, raw
	}
	// 4xx / rate-limit / greylisted / blocked = server won't tell us.
	return probeUnknown, raw
}

// ── Disposable domain list ────────────────────────────────────────────────────

var disposableDomains = map[string]bool{
	"mailinator.com": true, "guerrillamail.com": true, "tempmail.com": true,
	"throwam.com": true, "yopmail.com": true, "sharklasers.com": true,
	"guerrillamailblock.com": true, "grr.la": true, "guerrillamail.info": true,
	"guerrillamail.biz": true, "guerrillamail.de": true, "guerrillamail.net": true,
	"guerrillamail.org": true, "spam4.me": true, "trashmail.com": true,
	"trashmail.me": true, "trashmail.net": true, "dispostable.com": true,
	"maildrop.cc": true, "mailnull.com": true, "spamgourmet.com": true,
	"spamgourmet.net": true, "spamgourmet.org": true, "tempr.email": true,
	"discard.email": true, "spamhereplease.com": true, "tempinbox.com": true,
	"fakeinbox.com": true, "mailnesia.com": true, "spamevader.com": true,
	"appmaildev.com": true, "daerdy.com": true, "getairmail.com": true,
	"filzmail.com": true, "spamfree24.org": true, "wegwerfmail.de": true,
	"wegwerfmail.net": true, "0815.ru": true, "spamgob.com": true,
	"binkmail.com": true, "bobmail.info": true, "chammy.info": true,
	"devnullmail.com": true,
}

func isDisposable(domain string) bool {
	return disposableDomains[strings.ToLower(domain)]
}
