package delivery

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"net/smtp"
	"os"
	"strings"
	"sync"
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

// domainCooldownEntry holds the cooldown state for a remote domain.
type domainCooldownEntry struct {
	until  time.Time
	streak int // number of consecutive 421s
}

// ThrottleLimit holds per-user per-domain send-rate limits.
type ThrottleLimit struct {
	PerSec      int
	PerMin      int
	PerHour     int
	PerDay      int
	PerMonth    int
	IntervalSec int // min seconds between emails (e.g. 5 = 1 every 5 sec)
}

// throttleCounter tracks rolling send counts for one user+domain window.
type throttleCounter struct {
	secCount    int
	minCount    int
	hourCount   int
	dayCount    int
	monthCount  int
	secReset    time.Time
	minReset    time.Time
	hourReset   time.Time
	dayReset    time.Time
	monthReset  time.Time
	lastSendAt  time.Time // for IntervalSec
}

// IPDomainRule holds per-domain rate limits for an IP.
type IPDomainRule struct {
	Domain      string
	PerMin      int
	PerHour     int
	PerDay      int
	IntervalSec int
}

// IPEntry describes one outbound IP in the pool with optional rate limits.
// Hostname should match the IP's rDNS/PTR record — used as HELO when sending from this IP.
// DomainRules override base limits when sending to matching recipient domains.
type IPEntry struct {
	IP           string
	Hostname     string // rDNS hostname for this IP; used as HELO (must match PTR)
	PerMin       int    // 0 = unlimited (base; used when no domain rule matches)
	PerHour      int
	PerDay       int
	WarmupPerDay int // >0 when IP is in warmup phase; overrides PerDay
	IntervalSec  int // min seconds between emails from this IP
	DomainRules  []IPDomainRule
}

// SMTPRelay describes a custom outbound SMTP relay server.
type SMTPRelay struct {
	ID          uint
	Label       string
	Host        string
	Port        int
	Username    string
	Password    string
	TLSMode     string // "none" | "starttls" | "ssl"
	FromAddress string // override From when sending via this relay (required for rotation)
}

// ipCounter tracks rolling send counts for one outbound IP (or IP+domain).
type ipCounter struct {
	minCount   int
	hourCount  int
	dayCount   int
	minReset   time.Time
	hourReset  time.Time
	dayReset   time.Time
	lastSendAt time.Time // for IntervalSec
}

// Engine delivers queued messages to remote SMTP servers.
type Engine struct {
	cfg        config.DeliveryConfig
	queue      *queue.Queue
	retryBase  time.Duration
	connectTO  time.Duration
	dkimSigner *dkim.SignOptions
	OnEvent    func(DeliveryEvent) // optional hook for DB logging

	// DKIMKeyLoader optionally provides per-domain DKIM keys from the DB.
	DKIMKeyLoader func(domain string) (privKeyPEM, selector string, ok bool)

	// IPPoolProvider returns the active IP entries with per-IP rate limits.
	// Return nil or empty to use the system default IP.
	IPPoolProvider func() []IPEntry

	// UserSMTPProvider returns the SMTP delivery mode and custom relay list for a user.
	// mode: "system_only" | "custom_only" | "system_and_custom"
	// relays: active custom SMTP servers for the user (may be empty)
	UserSMTPProvider func(username string) (mode string, relays []SMTPRelay)

	// ThrottleProvider returns the effective send-rate limits for a user+domain pair.
	// Return a zero ThrottleLimit to skip throttling.
	ThrottleProvider func(username, domain string) ThrottleLimit

	// throttle counters: key is "username|domain"
	throttleMu       sync.Mutex
	throttleCounters map[string]*throttleCounter

	// SuppressionChecker returns true if the recipient has unsubscribed from this user's mail.
	SuppressionChecker func(username, email string) bool

	// UnsubBaseURL is the public base URL used to build List-Unsubscribe headers
	// (e.g. "https://mail.example.com"). Empty = feature disabled.
	UnsubBaseURL string

	// UnsubTokenFn generates a user-level HMAC token given a username.
	UnsubTokenFn func(username string) string

	// Per-user relay rotation tracking (guarded by userRelayMu).
	userRelayMu  sync.Mutex
	userRelayIdx map[string]int

	// Per-domain 421 cooldown tracking.
	cooldownMu sync.Mutex
	cooldowns  map[string]*domainCooldownEntry

	// Per-MX-host connection semaphores (max 2 concurrent per host).
	semMu sync.Mutex
	sems  map[string]chan struct{}

	// IP pool rotation + per-IP rate limiting (all guarded by ipMu).
	ipMu      sync.Mutex
	ipIdx     int
	ipCounters map[string]*ipCounter
}

// New creates a delivery Engine.
func New(cfg config.DeliveryConfig, q *queue.Queue) *Engine {
	e := &Engine{
		cfg:              cfg,
		queue:            q,
		cooldowns:        make(map[string]*domainCooldownEntry),
		sems:             make(map[string]chan struct{}),
		ipCounters:       make(map[string]*ipCounter),
		userRelayIdx:     make(map[string]int),
		throttleCounters: make(map[string]*throttleCounter),
	}

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
	// Log IP pool status so it is immediately visible in the console.
	go e.logIPPoolStatus()
}

// logIPPoolStatus prints a one-time diagnostic of the configured IP pool.
func (e *Engine) logIPPoolStatus() {
	if e.IPPoolProvider == nil {
		log.Printf("[IPPOOL] provider not configured — all mail uses system default IP")
		return
	}
	entries := e.IPPoolProvider()
	if len(entries) == 0 {
		log.Printf("[IPPOOL] pool is DISABLED or empty — all mail uses system default IP")
		log.Printf("[IPPOOL] ↳ To enable: Admin → IP Pool → check 'Enable IP Pool Rotation'")
		return
	}
	log.Printf("[IPPOOL] pool is ENABLED with %d IP(s):", len(entries))
	for _, ip := range entries {
		day := "∞"
		if ip.WarmupPerDay > 0 {
			day = fmt.Sprintf("%d (warmup)", ip.WarmupPerDay)
		} else if ip.PerDay > 0 {
			day = fmt.Sprintf("%d", ip.PerDay)
		}
		log.Printf("[IPPOOL]   %-18s  per-min=%-5v  per-hour=%-5v  per-day=%s",
			ip.IP,
			zeroOrInt(ip.PerMin),
			zeroOrInt(ip.PerHour),
			day,
		)
		// Quick local bind test — catches "IP not assigned to this server" immediately.
		if ln, err := net.Listen("tcp4", ip.IP+":0"); err != nil {
			log.Printf("[IPPOOL]   ✗ WARNING: cannot bind to %s: %v", ip.IP, err)
			log.Printf("[IPPOOL]     ↳ This IP may NOT be configured on the OS network interface.")
			log.Printf("[IPPOOL]     ↳ Mail sent using this IP will fall back to the system default.")
		} else {
			ln.Close()
			log.Printf("[IPPOOL]   ✓ bind test OK for %s", ip.IP)
		}
	}
}

func zeroOrInt(n int) string {
	if n == 0 {
		return "∞"
	}
	return fmt.Sprintf("%d", n)
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
			msg := e.queue.PopFair() // round-robin across users, not pure FIFO
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

	// ── Unsubscribe header injection ───────────────────────────────────────
	if e.UnsubBaseURL != "" && e.UnsubTokenFn != nil {
		token := e.UnsubTokenFn(msg.Username)
		unsubURL := e.UnsubBaseURL + "/unsub?t=" + token
		data = injectUnsubHeaders(data, unsubURL)
	}

	// ── Suppression filter — skip opted-out recipients ─────────────────────
	if e.SuppressionChecker != nil {
		var active []string
		for _, rcpt := range msg.To {
			if e.SuppressionChecker(msg.Username, rcpt) {
				log.Printf("[DELIVERY] ⏭ %s suppressed — skipping", rcpt)
				if e.OnEvent != nil {
					e.OnEvent(DeliveryEvent{
						MessageID: msg.ID, Username: msg.Username,
						From: msg.From, To: rcpt, Status: "suppressed",
						Error: "address is on unsubscribe/suppression list",
					})
				}
			} else {
				active = append(active, rcpt)
			}
		}
		if len(active) == 0 {
			log.Printf("[DELIVERY] ✓ message %s: all %d recipient(s) suppressed — done", msg.ID, len(msg.To))
			e.queue.Complete(msg.ID)
			return
		}
		if len(active) < len(msg.To) {
			// Replace msg with a filtered copy so remaining code uses active list.
			filtered := *msg
			filtered.To = active
			msg = &filtered
		}
	}

	// ── Custom SMTP relay routing ──────────────────────────────────────────
	// If a UserSMTPProvider is registered, check whether this user's messages
	// should be routed through a custom relay instead of direct MX delivery.
	if e.UserSMTPProvider != nil && msg.Username != "" {
		mode, relays := e.UserSMTPProvider(msg.Username)
		if mode == "custom_only" || mode == "system_and_custom" {
			relay := e.pickRelay(msg.Username, mode, relays)
			if relay != nil {
				log.Printf("[DELIVERY]   routing via custom relay %q (%s:%d)", relay.Label, relay.Host, relay.Port)
				fromAddr := msg.From
				relayData := data
				if relay.FromAddress != "" {
					fromAddr = relay.FromAddress
					relayData = rewriteFromHeader(data, fromAddr)
				}
				if err := e.deliverViaRelay(*relay, fromAddr, msg.To, relayData); err != nil {
					log.Printf("[DELIVERY] ✗ relay %q failed: %v", relay.Label, err)
					if isPermanentSMTPError(err) {
						if e.OnEvent != nil {
							for _, to := range msg.To {
								e.OnEvent(DeliveryEvent{
									MessageID: msg.ID, Username: msg.Username,
									From: msg.From, To: to, Status: "hard_bounce",
									Error: err.Error(), MXHost: relay.Host,
								})
							}
						}
						e.queue.Complete(msg.ID)
					} else {
						backoff := e.retryBase * (1 << uint(msg.RetryCount))
						if backoff > 24*time.Hour {
							backoff = 24 * time.Hour
						}
						e.queue.Defer(msg, backoff, err.Error())
						if e.OnEvent != nil {
							for _, to := range msg.To {
								e.OnEvent(DeliveryEvent{
									MessageID: msg.ID, Username: msg.Username,
									From: msg.From, To: to, Status: "deferred",
									Error: err.Error(), MXHost: relay.Host,
								})
							}
						}
					}
				} else {
					log.Printf("[DELIVERY] ✓ message %s relayed via %q SUCCESSFULLY", msg.ID, relay.Label)
					e.queue.Complete(msg.ID)
					if e.OnEvent != nil {
						for _, to := range msg.To {
							e.OnEvent(DeliveryEvent{
								MessageID: msg.ID, Username: msg.Username,
								From: msg.From, To: to, Status: "delivered",
								MXHost: relay.Host,
							})
						}
					}
				}
				return
			}
			// No relay available for custom_only → fail
			if mode == "custom_only" {
				log.Printf("[DELIVERY] ✗ message %s FAILED: no active custom SMTP for user %q", msg.ID, msg.Username)
				e.queue.Fail(msg, "no active custom SMTP configured")
				if e.OnEvent != nil {
					for _, to := range msg.To {
						e.OnEvent(DeliveryEvent{
							MessageID: msg.ID, Username: msg.Username,
							From: msg.From, To: to, Status: "failed",
							Error: "no active custom SMTP configured",
						})
					}
				}
				return
			}
			// system_and_custom with no relays → fall through to system delivery
		}
	}
	// ── end custom relay routing ───────────────────────────────────────────

	// Resolve DKIM signer: prefer per-domain key from DB, fallback to config key.
	signer := e.dkimSigner
	if e.DKIMKeyLoader != nil {
		fromDomain := extractFromDomain(data)
		if fromDomain != "" {
			if privPEM, sel, ok := e.DKIMKeyLoader(fromDomain); ok {
				if dbSigner, err := parseDKIMSignerFromPEM(fromDomain, sel, privPEM); err == nil {
					signer = dbSigner
					log.Printf("[DELIVERY]   using DB DKIM key for domain %q selector=%q", fromDomain, sel)
				}
			}
		}
	}
	if signer != nil {
		signed, err := signDKIM(data, signer)
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
	// hardBouncedRcpts tracks recipients that permanently failed (5xx).
	// These must never receive a "delivered" event.
	hardBouncedRcpts := make(map[string]bool)

	for domain, rcpts := range byDomain {
		log.Printf("[DELIVERY]   delivering to domain %q (%v)", domain, rcpts)

		// ── Per-user throttle check ───────────────────────────────────────────
		if reason, retryAfter := e.checkThrottle(msg.Username, domain, true); reason != "" {
			log.Printf("[DELIVERY] ⏳ %s", reason)
			if retryAfter < 5*time.Second {
				retryAfter = 5 * time.Second
			}
			e.queue.DeferNoIncrement(msg, retryAfter, reason)
			if e.OnEvent != nil {
				for _, rcpt := range rcpts {
					e.OnEvent(DeliveryEvent{
						MessageID: msg.ID, Username: msg.Username,
						From: msg.From, To: rcpt, Status: "deferred",
						Error: reason,
					})
				}
			}
			return
		}

		// onRcptBounce fires immediately when a single recipient gets a 5xx
		// during the RCPT TO phase — before DATA is ever sent.
		onRcptBounce := func(rcpt, reason string) {
			hardBouncedRcpts[rcpt] = true
			if e.OnEvent != nil {
				e.OnEvent(DeliveryEvent{
					MessageID: msg.ID, Username: msg.Username,
					From: msg.From, To: rcpt, Status: "hard_bounce",
					Error: reason,
				})
			}
		}

		mxHost, err := e.deliverToDomain(msg.From, domain, rcpts, data, onRcptBounce)
		if err != nil {
			log.Printf("[DELIVERY] ✗ domain %q failed: %v", domain, err)

			// IP pool exhausted — defer without burning a retry slot.
			if isIPPoolLimited(err) {
				var poolErr *ipPoolLimitedError
				errors.As(err, &poolErr)
				wait := poolErr.waitFor
				log.Printf("[IPPOOL] ⏳ message %s queued — waiting %v for an IP slot", msg.ID, wait)
				e.queue.DeferNoIncrement(msg, wait, err.Error())
				if e.OnEvent != nil {
					for _, rcpt := range rcpts {
						e.OnEvent(DeliveryEvent{
							MessageID: msg.ID, Username: msg.Username,
							From: msg.From, To: rcpt, Status: "deferred",
							Error: err.Error(),
						})
					}
				}
				return
			}

			if isPermanentSMTPError(err) {
				// Hard bounce — log event and remember these recipients so the
				// final "delivered" sweep never fires for them.
				log.Printf("[DELIVERY] ✗ hard bounce for domain %q", domain)
				for _, rcpt := range rcpts {
					hardBouncedRcpts[rcpt] = true
				}
				if e.OnEvent != nil {
					for _, rcpt := range rcpts {
						e.OnEvent(DeliveryEvent{
							MessageID: msg.ID, Username: msg.Username,
							From: msg.From, To: rcpt, Status: "hard_bounce",
							Error: err.Error(),
						})
					}
				}
				// Do NOT set lastErr — hard bounces are terminal per-recipient
				// and must not trigger global retries.
			} else if isTempRateLimitError(err) || strings.Contains(err.Error(), "rate-limited") {
				log.Printf("[DELIVERY] ⏳ domain %q is rate-limited — will defer (retries not consumed)", domain)
				lastErr = err
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
		// Count recipients that were actually delivered (not hard-bounced).
		deliveredRcpts := 0
		for _, to := range msg.To {
			if !hardBouncedRcpts[to] {
				deliveredRcpts++
			}
		}

		if deliveredRcpts > 0 {
			log.Printf("[DELIVERY] ✓ message %s DELIVERED SUCCESSFULLY (%d/%d recipients)",
				msg.ID, deliveredRcpts, len(msg.To))
		} else {
			log.Printf("[DELIVERY] ✗ message %s — all %d recipient(s) hard-bounced, removing from queue",
				msg.ID, len(msg.To))
		}

		// Remove from queue regardless — all recipients are definitively handled
		// (delivered or hard-bounced).
		e.queue.Complete(msg.ID)

		if e.OnEvent != nil {
			for _, to := range msg.To {
				if hardBouncedRcpts[to] {
					continue // hard_bounce event already emitted above
				}
				e.OnEvent(DeliveryEvent{
					MessageID: msg.ID, Username: msg.Username,
					From: msg.From, To: to, Status: "delivered",
					MXHost: recipientMX[to],
				})
			}
		}
		return
	}

	// If the failure is purely a 421 rate-limit, defer with a fixed cooldown
	// without consuming a retry slot so MaxRetries is reserved for real failures.
	isRateLimit := isTempRateLimitError(lastErr) || strings.Contains(lastErr.Error(), "rate-limited")
	if isRateLimit {
		// Use the domain's cooldown + a small buffer.
		backoff := 35 * time.Minute
		log.Printf("[DELIVERY] ⏳ message %s DEFERRED (rate-limited) — retry in %v (retries NOT consumed)",
			msg.ID, backoff)
		e.queue.DeferNoIncrement(msg, backoff, lastErr.Error())
		if e.OnEvent != nil {
			for _, to := range msg.To {
				e.OnEvent(DeliveryEvent{
					MessageID: msg.ID, Username: msg.Username,
					From: msg.From, To: to, Status: "deferred",
					Error: lastErr.Error(),
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

// isTempRateLimitError returns true when the SMTP server responded with a
// 421 temporary rate-limit (e.g. Yahoo TSS04, AOL similar codes).
func isTempRateLimitError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "421 4.7") ||
		strings.Contains(msg, "421 ") ||
		strings.Contains(msg, "TSS04") ||
		strings.Contains(msg, "temporarily deferred") ||
		strings.Contains(msg, "temp") && strings.HasPrefix(msg, "421")
}

// domainCooldownUntil returns the time until which the domain should not be
// attempted, or zero if it is allowed.
func (e *Engine) domainCooldownUntil(domain string) time.Time {
	e.cooldownMu.Lock()
	defer e.cooldownMu.Unlock()
	if c, ok := e.cooldowns[domain]; ok {
		return c.until
	}
	return time.Time{}
}

// recordRateLimit records a 421 hit for a domain and extends its cooldown.
// Each consecutive hit doubles the backoff: 15m → 30m → 60m → 120m (cap).
func (e *Engine) recordRateLimit(domain string) time.Duration {
	e.cooldownMu.Lock()
	defer e.cooldownMu.Unlock()
	c, ok := e.cooldowns[domain]
	if !ok {
		c = &domainCooldownEntry{}
		e.cooldowns[domain] = c
	}
	c.streak++
	backoff := time.Duration(15*c.streak) * time.Minute
	if backoff > 2*time.Hour {
		backoff = 2 * time.Hour
	}
	c.until = time.Now().Add(backoff)
	log.Printf("[DELIVERY] ⏳ domain %q rate-limited (421) — cooldown %v until %s (streak=%d)",
		domain, backoff, c.until.Format("15:04:05"), c.streak)
	return backoff
}

// clearCooldown resets the rate-limit streak for a domain after a success.
func (e *Engine) clearCooldown(domain string) {
	e.cooldownMu.Lock()
	defer e.cooldownMu.Unlock()
	delete(e.cooldowns, domain)
}

// acquireMXSlot blocks until a connection slot is available for the MX host.
// Max 2 concurrent connections per MX host (Yahoo/AOL requirement).
func (e *Engine) acquireMXSlot(mxHost string) {
	e.semMu.Lock()
	sem, ok := e.sems[mxHost]
	if !ok {
		sem = make(chan struct{}, 2) // max 2 concurrent per MX
		e.sems[mxHost] = sem
	}
	e.semMu.Unlock()
	sem <- struct{}{}
}

func (e *Engine) releaseMXSlot(mxHost string) {
	e.semMu.Lock()
	sem := e.sems[mxHost]
	e.semMu.Unlock()
	<-sem
}

// deliverToDomain attempts delivery to a domain, returning the successful MX host on success.
// onRcptBounce is called for each recipient that receives a permanent 5xx during RCPT TO.
// Those recipients are skipped from DATA; the remaining valid recipients are delivered.
func (e *Engine) deliverToDomain(from, domain string, rcpts []string, data []byte,
	onRcptBounce func(rcpt, reason string)) (string, error) {
	// Check per-domain 421 cooldown before doing anything.
	if until := e.domainCooldownUntil(domain); !until.IsZero() && time.Now().Before(until) {
		wait := time.Until(until).Round(time.Second)
		log.Printf("[DELIVERY] ⏳ domain %q is rate-limited — skipping for %v", domain, wait)
		return "", fmt.Errorf("domain rate-limited (421 cooldown), retry after %v", wait)
	}

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

	var lastMXErr error
	allRateLimited := true

	for _, mx := range mxRecords {
		for _, port := range deliveryPorts {
			log.Printf("[DELIVERY]   trying MX %s port=%s (pref=%d)", mx.Host, port, mx.Pref)

			// Respect per-MX connection limit.
			e.acquireMXSlot(mx.Host)
			mxErr := e.sendToMX(from, domain, mx.Host, port, rcpts, data, onRcptBounce)
			e.releaseMXSlot(mx.Host)

			if mxErr == nil {
				log.Printf("[DELIVERY] ✓ delivered via MX %s:%s", mx.Host, port)
				e.clearCooldown(domain) // success — reset streak
				return mx.Host, nil
			}
			log.Printf("[DELIVERY] ✗ MX %s:%s failed: %v", mx.Host, port, mxErr)

			// 5xx permanent failure (mailbox not found, user rejected, etc.) —
			// all MX hosts will give the same answer, so stop immediately and
			// return the 5xx error so the caller can hard-bounce.
			// IP pool limited — all our outbound IPs are at capacity.
			// Return immediately; no point trying other MX hosts.
			if isIPPoolLimited(mxErr) {
				return "", mxErr
			}

			if isPermanentSMTPError(mxErr) {
				log.Printf("[DELIVERY] ✗ permanent 5xx from %s — stopping MX attempts for %q", mx.Host, domain)
				return "", mxErr
			}

			if isTempRateLimitError(mxErr) {
				lastMXErr = mxErr
				// Continue to next MX/port, but remember all were rate-limited.
			} else {
				allRateLimited = false
				lastMXErr = mxErr
			}
		}
	}

	// If every MX returned a 421, set a domain-level cooldown and return a
	// deferred-style error (not a hard bounce — no permanent failure).
	if allRateLimited && lastMXErr != nil {
		cooldown := e.recordRateLimit(domain)
		return "", fmt.Errorf("all MX servers rate-limited (421) for %s — cooling down %v: %w",
			domain, cooldown, lastMXErr)
	}
	return "", fmt.Errorf("all MX servers failed for %s: %w", domain, lastMXErr)
}

// ipPoolLimitedError is returned when the IP pool is active but every IP has
// reached its rate limit. The embedded waitFor is the shortest time until any
// IP's counter window resets, so the message can be deferred precisely.
type ipPoolLimitedError struct {
	waitFor time.Duration
}

func (e *ipPoolLimitedError) Error() string {
	return fmt.Sprintf("ip pool: all IPs rate-limited — retry in %v", e.waitFor)
}

// ipEffectiveLimits returns per-min/hour/day and interval for an IP+domain.
func (entry *IPEntry) ipEffectiveLimits(domain string) (perMin, perHour, perDay, intervalSec int) {
	domain = strings.ToLower(domain)
	for _, r := range entry.DomainRules {
		if r.Domain == domain {
			perMin, perHour, perDay = r.PerMin, r.PerHour, r.PerDay
			if r.IntervalSec > 0 {
				intervalSec = r.IntervalSec
			} else {
				intervalSec = entry.IntervalSec
			}
			return
		}
	}
	return entry.PerMin, entry.PerHour, entry.PerDay, entry.IntervalSec
}

// nextOutboundIP selects the next available IP from the pool using round-robin.
// domain is the recipient domain (e.g. gmail.com) for domain-specific rate limits.
// Returns:
//   - (ip, hostname, nil) — ip selected; hostname is the IP's rDNS (for HELO); counters reserved
//   - ("", "", nil)      — pool disabled/empty; use system default IP and global HELO
//   - ("", "", limitedErr) — pool active but all IPs rate-limited; caller must defer
func (e *Engine) nextOutboundIP(domain string) (ip, hostname string, err error) {
	if e.IPPoolProvider == nil {
		return "", "", nil
	}
	entries := e.IPPoolProvider()
	if len(entries) == 0 {
		return "", "", nil // pool disabled or empty → fall through to system default
	}

	e.ipMu.Lock()
	defer e.ipMu.Unlock()

	now := time.Now()
	n := len(entries)

	for i := 0; i < n; i++ {
		entry := entries[(e.ipIdx+i)%n]
		perMin, perHour, perDay, intervalSec := entry.ipEffectiveLimits(domain)

		// Counter key: ip|domain for per-domain tracking
		counterKey := entry.IP + "|" + domain
		c, ok := e.ipCounters[counterKey]
		if !ok {
			c = &ipCounter{
				minReset:  now.Add(time.Minute),
				hourReset: now.Add(time.Hour),
				dayReset:  now.Add(24 * time.Hour),
			}
			e.ipCounters[counterKey] = c
		}

		if now.After(c.minReset) {
			c.minCount = 0
			c.minReset = now.Add(time.Minute)
		}
		if now.After(c.hourReset) {
			c.hourCount = 0
			c.hourReset = now.Add(time.Hour)
		}
		if now.After(c.dayReset) {
			c.dayCount = 0
			c.dayReset = now.Add(24 * time.Hour)
		}

		effectivePerDay := perDay
		if entry.WarmupPerDay > 0 {
			effectivePerDay = entry.WarmupPerDay
			if perDay > 0 && perDay < effectivePerDay {
				effectivePerDay = perDay
			}
		}

		if intervalSec > 0 && !c.lastSendAt.IsZero() {
			elapsed := time.Since(c.lastSendAt).Seconds()
			if elapsed < float64(intervalSec) {
				wait := time.Duration(intervalSec)*time.Second - time.Duration(elapsed*float64(time.Second))
				log.Printf("[IPPOOL]   IP %s: interval %ds not met for %s (wait %v)", entry.IP, intervalSec, domain, wait.Round(time.Second))
				continue
			}
		}

		if perMin > 0 && c.minCount >= perMin {
			log.Printf("[IPPOOL]   IP %s: per-min limit %d reached for %s, skipping", entry.IP, perMin, domain)
			continue
		}
		if perHour > 0 && c.hourCount >= perHour {
			log.Printf("[IPPOOL]   IP %s: per-hour limit %d reached for %s, skipping", entry.IP, perHour, domain)
			continue
		}
		if effectivePerDay > 0 && c.dayCount >= effectivePerDay {
			log.Printf("[IPPOOL]   IP %s: per-day limit %d reached for %s, skipping", entry.IP, effectivePerDay, domain)
			continue
		}

		c.minCount++
		c.hourCount++
		c.dayCount++
		c.lastSendAt = now
		e.ipIdx = (e.ipIdx + i + 1) % n
		return entry.IP, entry.Hostname, nil
	}

	minWait := 24 * time.Hour
	for _, entry := range entries {
		perMin, perHour, perDay, intervalSec := entry.ipEffectiveLimits(domain)
		counterKey := entry.IP + "|" + domain
		c, ok := e.ipCounters[counterKey]
		if !ok {
			minWait = time.Minute
			break
		}
		if intervalSec > 0 && !c.lastSendAt.IsZero() {
			elapsed := time.Since(c.lastSendAt).Seconds()
			if elapsed < float64(intervalSec) {
				w := time.Duration(intervalSec)*time.Second - time.Duration(elapsed*float64(time.Second))
				if w > 0 && w < minWait {
					minWait = w
				}
			}
		}
		if perMin > 0 && c.minCount >= perMin {
			if w := time.Until(c.minReset); w > 0 && w < minWait {
				minWait = w
			}
		}
		if perHour > 0 && c.hourCount >= perHour {
			if w := time.Until(c.hourReset); w > 0 && w < minWait {
				minWait = w
			}
		}
		if perDay > 0 && c.dayCount >= perDay {
			if w := time.Until(c.dayReset); w > 0 && w < minWait {
				minWait = w
			}
		}
	}
	if minWait <= 0 {
		minWait = time.Minute
	}
	log.Printf("[IPPOOL] ⏳ all pool IPs rate-limited — deferring message, retry in %v", minWait)
	return "", "", &ipPoolLimitedError{waitFor: minWait}
}

// undoIPCount returns a previously reserved rate-limit slot for an IP+domain.
func (e *Engine) undoIPCount(ip, domain string) {
	e.ipMu.Lock()
	defer e.ipMu.Unlock()
	key := ip + "|" + domain
	if c, ok := e.ipCounters[key]; ok {
		if c.minCount > 0 {
			c.minCount--
		}
		if c.hourCount > 0 {
			c.hourCount--
		}
		if c.dayCount > 0 {
			c.dayCount--
		}
	}
}

// checkThrottle checks whether the user is within rate limits for the given domain.
// Returns ("", 0) if allowed, or (reason, retryAfter) if throttled.
// Also increments counters when allowed (consume = true).
func (e *Engine) checkThrottle(username, domain string, consume bool) (reason string, retryAfter time.Duration) {
	if e.ThrottleProvider == nil || username == "" {
		return "", 0
	}
	lim := e.ThrottleProvider(username, domain)
	if lim.PerSec == 0 && lim.PerMin == 0 && lim.PerHour == 0 && lim.PerDay == 0 && lim.PerMonth == 0 && lim.IntervalSec == 0 {
		return "", 0 // no limits configured
	}

	key := username + "|" + domain
	e.throttleMu.Lock()
	defer e.throttleMu.Unlock()

	now := time.Now()
	c, ok := e.throttleCounters[key]
	if !ok {
		c = &throttleCounter{
			secReset:   now.Add(time.Second),
			minReset:   now.Add(time.Minute),
			hourReset:  now.Add(time.Hour),
			dayReset:   now.Add(24 * time.Hour),
			monthReset: now.Add(30 * 24 * time.Hour),
		}
		e.throttleCounters[key] = c
	}

	// Reset expired windows.
	if now.After(c.secReset)   { c.secCount = 0;   c.secReset   = now.Add(time.Second)         }
	if now.After(c.minReset)   { c.minCount = 0;   c.minReset   = now.Add(time.Minute)          }
	if now.After(c.hourReset)  { c.hourCount = 0;  c.hourReset  = now.Add(time.Hour)            }
	if now.After(c.dayReset)   { c.dayCount = 0;   c.dayReset   = now.Add(24 * time.Hour)       }
	if now.After(c.monthReset) { c.monthCount = 0; c.monthReset = now.Add(30 * 24 * time.Hour)  }

	// IntervalSec: min seconds between emails (e.g. 5 = 1 email every 5 sec)
	if lim.IntervalSec > 0 && !c.lastSendAt.IsZero() {
		elapsed := time.Since(c.lastSendAt).Seconds()
		if elapsed < float64(lim.IntervalSec) {
			wait := time.Duration(lim.IntervalSec)*time.Second - time.Duration(elapsed*float64(time.Second))
			return fmt.Sprintf("user %q: wait %ds between emails for %s", username, lim.IntervalSec, domain), wait
		}
	}

	// Check limits.
	if lim.PerSec > 0 && c.secCount >= lim.PerSec {
		return fmt.Sprintf("user %q throttled to %d/sec for domain %s", username, lim.PerSec, domain),
			time.Until(c.secReset)
	}
	if lim.PerMin > 0 && c.minCount >= lim.PerMin {
		return fmt.Sprintf("user %q throttled to %d/min for domain %s", username, lim.PerMin, domain),
			time.Until(c.minReset)
	}
	if lim.PerHour > 0 && c.hourCount >= lim.PerHour {
		return fmt.Sprintf("user %q throttled to %d/hr for domain %s", username, lim.PerHour, domain),
			time.Until(c.hourReset)
	}
	if lim.PerDay > 0 && c.dayCount >= lim.PerDay {
		return fmt.Sprintf("user %q throttled to %d/day for domain %s", username, lim.PerDay, domain),
			time.Until(c.dayReset)
	}
	if lim.PerMonth > 0 && c.monthCount >= lim.PerMonth {
		return fmt.Sprintf("user %q throttled to %d/month for domain %s", username, lim.PerMonth, domain),
			time.Until(c.monthReset)
	}

	// Allowed — consume a slot.
	if consume {
		c.secCount++
		c.minCount++
		c.hourCount++
		c.dayCount++
		c.monthCount++
		c.lastSendAt = now
	}
	return "", 0
}

// pickRelay selects the next relay for a user using round-robin rotation.
// For system_and_custom mode, index 0 means "use system MX delivery" (returns nil).
// For custom_only, only custom relays are in the pool.
func (e *Engine) pickRelay(username, mode string, relays []SMTPRelay) *SMTPRelay {
	if len(relays) == 0 {
		return nil
	}

	e.userRelayMu.Lock()
	defer e.userRelayMu.Unlock()

	// Build the pool: for system_and_custom, slot 0 = system (nil), then custom relays.
	poolSize := len(relays)
	systemSlot := false
	if mode == "system_and_custom" {
		poolSize++
		systemSlot = true
	}

	idx := e.userRelayIdx[username] % poolSize
	e.userRelayIdx[username] = (idx + 1) % poolSize

	if systemSlot && idx == 0 {
		return nil // caller should use system MX delivery
	}
	relayIdx := idx
	if systemSlot {
		relayIdx = idx - 1
	}
	if relayIdx < 0 || relayIdx >= len(relays) {
		return nil
	}
	r := relays[relayIdx]
	return &r
}

// deliverViaRelay sends all recipients of a message through an authenticated SMTP relay.
func (e *Engine) deliverViaRelay(relay SMTPRelay, from string, rcpts []string, data []byte) error {
	addr := fmt.Sprintf("%s:%d", relay.Host, relay.Port)
	tlsMode := relay.TLSMode
	if tlsMode == "" {
		tlsMode = "starttls"
	}
	log.Printf("[DELIVERY]   relay connecting to %s (TLS: %s) …", addr, tlsMode)

	var conn net.Conn
	var err error
	if tlsMode == "ssl" {
		tlsCfg := &tls.Config{ServerName: relay.Host, MinVersion: tls.VersionTLS12}
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: e.connectTO}, "tcp4", addr, tlsCfg)
		if err != nil {
			return fmt.Errorf("relay TLS dial %s: %w", addr, err)
		}
		log.Printf("[DELIVERY]   relay TLS connected to %s", addr)
	} else {
		conn, err = net.DialTimeout("tcp4", addr, e.connectTO)
		if err != nil {
			return fmt.Errorf("relay dial %s: %w", addr, err)
		}
		log.Printf("[DELIVERY]   relay TCP connected to %s", addr)
	}
	defer conn.Close()

	heloName := e.cfg.HeloName
	if heloName == "" {
		heloName = "localhost"
	}

	client, err := smtp.NewClient(conn, relay.Host)
	if err != nil {
		return fmt.Errorf("relay new client: %w", err)
	}
	defer client.Close()

	if err := client.Hello(heloName); err != nil {
		return fmt.Errorf("relay EHLO: %w", err)
	}

	if tlsMode == "starttls" {
		if ok, _ := client.Extension("STARTTLS"); ok {
			tlsCfg := &tls.Config{ServerName: relay.Host, MinVersion: tls.VersionTLS12}
			if err := client.StartTLS(tlsCfg); err != nil {
				log.Printf("[DELIVERY]   relay STARTTLS failed (%v), continuing plain", err)
			} else {
				log.Printf("[DELIVERY]   relay STARTTLS ok")
			}
		}
	}

	if relay.Username != "" {
		auth := smtp.PlainAuth("", relay.Username, relay.Password, relay.Host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("relay AUTH: %w", err)
		}
		log.Printf("[DELIVERY]   relay AUTH ok (user=%s)", relay.Username)
	}

	if err := client.Mail(from); err != nil {
		return fmt.Errorf("relay MAIL FROM <%s>: %w", from, err)
	}
	for _, rcpt := range rcpts {
		if err := client.Rcpt(rcpt); err != nil {
			return fmt.Errorf("relay RCPT TO <%s>: %w", rcpt, err)
		}
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("relay DATA: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("relay write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("relay DATA close: %w", err)
	}
	log.Printf("[DELIVERY]   relay DATA sent (%d bytes) → ok", len(data))
	client.Quit()
	return nil
}

func (e *Engine) sendToMX(from, domain, mxHost, port string, rcpts []string, data []byte,
	onRcptBounce func(rcpt, reason string)) error {
	addr := net.JoinHostPort(mxHost, port)
	log.Printf("[DELIVERY]   connecting to %s …", addr)

	var conn net.Conn
	var err error

	outIP, outHostname, ipErr := e.nextOutboundIP(domain)
	if ipErr != nil {
		// Pool is active but ALL IPs are rate-limited — signal the caller to defer.
		return ipErr
	}
	usedPoolIP := false
	if outIP != "" {
		dialer := &net.Dialer{
			Timeout:   e.connectTO,
			LocalAddr: &net.TCPAddr{IP: net.ParseIP(outIP)},
		}
		log.Printf("[IPPOOL]   selected outbound IP %s → %s", outIP, addr)
		conn, err = dialer.Dial("tcp4", addr)
		if err != nil {
			// Binding to this pool IP failed (not assigned to interface or OS error).
			// Undo the reservation so the counter stays accurate, then fall back.
			e.undoIPCount(outIP, domain)
			log.Printf("[IPPOOL] ✗ bind to %s FAILED: %v", outIP, err)
			log.Printf("[IPPOOL]   ↳ IP may not be configured on the OS network interface.")
			log.Printf("[IPPOOL]   ↳ Falling back to system default IP for this connection.")
			conn, err = net.DialTimeout("tcp4", addr, e.connectTO)
		} else {
			usedPoolIP = true
		}
	} else {
		// Pool is disabled/empty — use system default IP.
		conn, err = net.DialTimeout("tcp4", addr, e.connectTO)
	}
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	log.Printf("[DELIVERY]   TCP connected to %s", addr)

	// HELO must match rDNS/PTR for the outbound IP. If we used a pool IP with a hostname, use it.
	heloName := e.cfg.HeloName
	if heloName == "" {
		heloName = "localhost"
	}
	if usedPoolIP && outHostname != "" {
		heloName = outHostname
		log.Printf("[IPPOOL]   HELO %s (matches rDNS for %s)", heloName, outIP)
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

	// ── RCPT TO — per-recipient handling ──────────────────────────────────
	// A 5xx on RCPT TO is a permanent per-recipient rejection (mailbox not
	// found, user suspended, etc.).  We call the bounce callback for that
	// recipient and continue trying the remaining ones so a single bad
	// address never blocks a valid one in the same batch.
	// If ALL recipients are rejected we abort immediately; DATA is never sent.
	var accepted []string
	var lastRcptBounceErr error
	for _, rcpt := range rcpts {
		if err := client.Rcpt(rcpt); err != nil {
			if isPermanentSMTPError(err) {
				reason := fmt.Sprintf("RCPT TO <%s>: %v", rcpt, err)
				log.Printf("[DELIVERY] ✗ RCPT TO <%s> → hard bounce (5xx) — aborting for this recipient: %v",
					rcpt, err)
				if onRcptBounce != nil {
					onRcptBounce(rcpt, reason)
				}
				lastRcptBounceErr = fmt.Errorf("%s: %w", reason, err)
				continue // skip to next recipient — do NOT abort the whole session yet
			}
			// Temporary RCPT error — abort and retry later.
			log.Printf("[DELIVERY] ✗ RCPT TO <%s> → temp error (will retry): %v", rcpt, err)
			client.Quit()
			return fmt.Errorf("RCPT TO <%s>: %w", rcpt, err)
		}
		log.Printf("[DELIVERY]   RCPT TO <%s> → ok", rcpt)
		accepted = append(accepted, rcpt)
	}

	if len(accepted) == 0 {
		// Every recipient was permanently rejected — abort without sending DATA.
		log.Printf("[DELIVERY] ✗ all %d recipient(s) hard-bounced during RCPT — session aborted, DATA not sent",
			len(rcpts))
		client.Quit()
		// Return the last bounce error so isPermanentSMTPError fires in the caller.
		return lastRcptBounceErr
	}
	if len(accepted) < len(rcpts) {
		log.Printf("[DELIVERY]   %d/%d recipient(s) accepted for DATA (rest hard-bounced)",
			len(accepted), len(rcpts))
	}
	// ── end RCPT TO ────────────────────────────────────────────────────────

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("DATA: %w", err)
	}
	n, err := w.Write(data)
	if err != nil {
		return fmt.Errorf("write body: %w", err)
	}
	if err := w.Close(); err != nil {
		// A 5xx DATA close is also a permanent rejection.
		return fmt.Errorf("DATA close: %w", err)
	}
	log.Printf("[DELIVERY]   DATA sent (%d bytes) to %d recipient(s) → ok", n, len(accepted))

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

// injectUnsubHeaders prepends List-Unsubscribe and List-Unsubscribe-Post headers
// if they are not already present. This makes the message compliant with Gmail/Yahoo
// bulk sender requirements (Feb 2024).
func injectUnsubHeaders(data []byte, unsubURL string) []byte {
	header, body, found := bytes.Cut(data, []byte("\r\n\r\n"))
	if !found {
		header, body, found = bytes.Cut(data, []byte("\n\n"))
		if !found {
			return data
		}
	}
	headerStr := string(header)
	if containsHeader(headerStr, "List-Unsubscribe") {
		return data // already present, respect sender's own header
	}
	inject := fmt.Sprintf(
		"List-Unsubscribe: <%s>\r\nList-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n",
		unsubURL,
	)
	sep := "\r\n\r\n"
	if !found {
		sep = "\n\n"
	}
	return []byte(inject + headerStr + sep + string(body))
}

func containsHeader(header, name string) bool {
	lower := strings.ToLower(header)
	return strings.Contains(lower, "\n"+strings.ToLower(name)+":") ||
		strings.HasPrefix(lower, strings.ToLower(name)+":")
}

// rewriteFromHeader replaces the From header in raw RFC 5322 data with the given address.
// Used when sending via custom relay with FromAddress override.
func rewriteFromHeader(data []byte, fromAddr string) []byte {
	header, body, found := bytes.Cut(data, []byte("\r\n\r\n"))
	if !found {
		header, body, found = bytes.Cut(data, []byte("\n\n"))
		if !found {
			return data
		}
	}
	sep := "\r\n\r\n"
	if !bytes.Contains(data, []byte("\r\n\r\n")) {
		sep = "\n\n"
	}
	fromLine := "From: <" + fromAddr + ">"
	if strings.Contains(fromAddr, "<") {
		fromLine = "From: " + fromAddr
	}
	lines := strings.Split(strings.ReplaceAll(string(header), "\r\n", "\n"), "\n")
	var out []string
	skipUntilNextHeader := false
	replaced := false
	for _, line := range lines {
		if line == "" {
			out = append(out, line)
			break
		}
		if skipUntilNextHeader {
			if line[0] == ' ' || line[0] == '\t' {
				continue // skip folded continuation
			}
			skipUntilNextHeader = false
		}
		lower := strings.ToLower(strings.TrimSpace(line))
		if strings.HasPrefix(lower, "from:") {
			out = append(out, fromLine)
			skipUntilNextHeader = true
			replaced = true
			continue
		}
		out = append(out, line)
	}
	if !replaced {
		out = append([]string{fromLine}, out...)
	}
	return []byte(strings.ReplaceAll(strings.Join(out, "\n"), "\n", "\r\n") + sep + string(body))
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

// extractFromDomain parses the sender domain from the From: header of raw RFC 5322 data.
func extractFromDomain(data []byte) string {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break // end of headers
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "from:") {
			addr := strings.TrimSpace(line[5:])
			if s := strings.LastIndex(addr, "<"); s >= 0 {
				if e := strings.Index(addr[s:], ">"); e >= 0 {
					addr = addr[s+1 : s+e]
				}
			}
			if at := strings.LastIndex(addr, "@"); at >= 0 {
				return strings.ToLower(strings.TrimSpace(addr[at+1:]))
			}
		}
	}
	return ""
}

// parseDKIMSignerFromPEM builds a dkim.SignOptions from a PEM-encoded PKCS1 private key.
func parseDKIMSignerFromPEM(domain, selector, privKeyPEM string) (*dkim.SignOptions, error) {
	block, _ := pem.Decode([]byte(privKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("invalid PEM block")
	}
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse RSA key: %w", err)
	}
	return &dkim.SignOptions{
		Domain:   domain,
		Selector: selector,
		Signer:   privKey,
		HeaderKeys: []string{
			"From", "To", "Subject", "Date", "Message-ID", "Content-Type",
		},
	}, nil
}

// IPCounterSnapshot holds a point-in-time view of send counters for one IP.
type IPCounterSnapshot struct {
	MinCount  int
	HourCount int
	DayCount  int
}

// GetIPStats returns the current in-memory send counters for every tracked IP.
// Keys are "ip|domain"; we aggregate by IP for display.
func (e *Engine) GetIPStats() map[string]IPCounterSnapshot {
	e.ipMu.Lock()
	defer e.ipMu.Unlock()
	result := make(map[string]IPCounterSnapshot)
	for key, c := range e.ipCounters {
		ip := key
		if idx := strings.Index(key, "|"); idx > 0 {
			ip = key[:idx]
		}
		s := result[ip]
		s.MinCount += c.minCount
		s.HourCount += c.hourCount
		s.DayCount += c.dayCount
		result[ip] = s
	}
	return result
}

// isIPPoolLimited returns true when the error was caused by all pool IPs being
// at their rate limit (the message should be deferred, not failed).
func isIPPoolLimited(err error) bool {
	var e *ipPoolLimitedError
	return errors.As(err, &e)
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
