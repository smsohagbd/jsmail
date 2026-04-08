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

	major := isMajorProvider(domain)

	// ── 4. SMTP probe ─────────────────────────────────────────────────────────
	// For major providers (Yahoo, Gmail, etc.) we do a single RCPT TO probe and
	// trust the response — they reliably reject unknown mailboxes with 5xx errors.
	// We skip the catch-all double-probe for them because they use DHA protection
	// (accept all RCPT TO from unknown IPs), which would cause false "catch-all"
	// results for valid addresses.
	// For unknown / small domains we run the full double-probe to detect catch-alls.
	smtpResult, catchAll := v.smtpProbe(email, mxHost, major)
	r.IsCatchAll = catchAll

	switch smtpResult {
	case probeExists:
		r.Checks.SMTPConnect = StatusPass
		if catchAll {
			r.Checks.Mailbox = StatusUnknown
			r.Valid = false
			r.Reason = "catch-all server — individual mailbox cannot be verified (high bounce risk)"
		} else {
			r.Checks.Mailbox = StatusPass
			r.Valid = true
		}
	case probeNotFound:
		r.Checks.SMTPConnect = StatusPass
		r.Checks.Mailbox = StatusFail
		r.Valid = false
		r.Reason = "mailbox does not exist"
	case probeConnectFail:
		r.Checks.SMTPConnect = StatusFail
		r.Checks.Mailbox = StatusUnknown
		if major {
			// Major providers are always reachable; a connect failure is transient.
			// Give benefit of the doubt so we don't wrongly suppress valid addresses.
			r.Valid = true
			r.Reason = "could not connect to mail server (transient)"
		} else {
			r.Valid = false
			r.Reason = "could not connect to mail server"
		}
	case probeUnknown:
		r.Checks.SMTPConnect = StatusPass
		r.Checks.Mailbox = StatusUnknown
		if major {
			// Major providers sometimes rate-limit probes without that meaning the
			// address is bad. Treat unknown response as valid for them.
			r.Valid = true
			r.Reason = "server did not confirm mailbox (major provider — assumed valid)"
		} else {
			r.Valid = false
			r.Reason = "server blocked probe — cannot verify mailbox"
		}
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

func (v *Verifier) smtpProbe(email, mxHost string, majorProvider bool) (probeResult, bool) {
	conn, err := net.DialTimeout("tcp4", net.JoinHostPort(mxHost, "25"), v.cfg.ConnectTimeout)
	if err != nil {
		// Fallback to port 587
		conn, err = net.DialTimeout("tcp4", net.JoinHostPort(mxHost, "587"), v.cfg.ConnectTimeout)
		if err != nil {
			return probeConnectFail, false
		}
	}

	client, err := smtp.NewClient(conn, mxHost)
	if err != nil {
		conn.Close()
		return probeConnectFail, false
	}
	defer client.Close()

	if err := client.Hello(v.cfg.HeloName); err != nil {
		return probeConnectFail, false
	}

	// Upgrade to TLS if available.
	if ok, _ := client.Extension("STARTTLS"); ok {
		tlsCfg := &tls.Config{ServerName: mxHost, InsecureSkipVerify: false}
		client.StartTLS(tlsCfg) // non-fatal if fails
	}

	if err := client.Mail(v.cfg.ProbeFrom); err != nil {
		// Some servers reject our MAIL FROM — treat as unknown.
		return probeUnknown, false
	}

	result := rcptProbe(client, email)
	if result != probeExists {
		return result, false
	}

	// Major providers (Yahoo, Gmail, Outlook …) use DHA protection and accept
	// every RCPT TO from unknown IPs. Running a double-probe on them would always
	// look like a catch-all, causing valid addresses to be wrongly rejected.
	// Trust the single 250 response for them.
	if majorProvider {
		return probeExists, false
	}

	// For unknown domains: send a second RCPT TO with a random address.
	// If that also gets accepted the server is a catch-all.
	domain := strings.SplitN(email, "@", 2)[1]
	randomAddr := fmt.Sprintf("verify-check-%d@%s", time.Now().UnixNano(), domain)
	catchAllResult := rcptProbe(client, randomAddr)
	if catchAllResult == probeExists {
		return probeExists, true
	}

	return probeExists, false
}

func rcptProbe(client *smtp.Client, addr string) probeResult {
	err := client.Rcpt(addr)
	if err == nil {
		return probeExists
	}
	msg := strings.ToLower(err.Error())
	// Permanent 5xx rejections = mailbox not found.
	if strings.HasPrefix(err.Error(), "55") ||
		strings.Contains(msg, "no such user") ||
		strings.Contains(msg, "user unknown") ||
		strings.Contains(msg, "does not exist") ||
		strings.Contains(msg, "invalid address") ||
		strings.Contains(msg, "mailbox not found") ||
		strings.Contains(msg, "not a valid recipient") ||
		strings.Contains(msg, "doesn't have a yahoo.com account") ||
		strings.Contains(msg, "bad destination") {
		return probeNotFound
	}
	// 4xx or other = server won't tell us.
	return probeUnknown
}

// ── Major provider list ───────────────────────────────────────────────────────
// These providers use DHA protection and block SMTP probing from unknown IPs.
// We trust format + MX check only for them — SMTP probe would give false results.
var majorProviders = map[string]bool{
	// Yahoo family
	"yahoo.com": true, "yahoo.co.uk": true, "yahoo.co.in": true, "yahoo.co.jp": true,
	"yahoo.fr": true, "yahoo.de": true, "yahoo.es": true, "yahoo.it": true,
	"yahoo.com.br": true, "yahoo.com.au": true, "yahoo.com.ar": true,
	"ymail.com": true, "rocketmail.com": true,
	// Google / Gmail
	"gmail.com": true, "googlemail.com": true,
	// Microsoft
	"hotmail.com": true, "hotmail.co.uk": true, "hotmail.fr": true,
	"hotmail.de": true, "hotmail.it": true, "hotmail.es": true,
	"outlook.com": true, "outlook.co.uk": true, "outlook.fr": true,
	"live.com": true, "live.co.uk": true, "live.fr": true,
	"msn.com": true,
	// AOL / Verizon Media
	"aol.com": true, "aim.com": true, "verizon.net": true,
	// Apple
	"icloud.com": true, "me.com": true, "mac.com": true,
	// Other large providers
	"protonmail.com": true, "proton.me": true,
	"zoho.com": true,
	"mail.com": true,
}

func isMajorProvider(domain string) bool {
	return majorProviders[strings.ToLower(domain)]
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
