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
	mathrand "math/rand"
	"net"
	"net/smtp"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/emersion/go-msgauth/dkim"

	"smtp-server/internal/config"
	"smtp-server/internal/email"
	"smtp-server/internal/queue"
	"smtp-server/internal/smtprelay"
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
	// Per-relay sending rate limits. 0 = unlimited.
	LimitPerMin  int
	LimitPerHour int
	LimitPerDay  int
	// When true, each recipient is verified before the message is forwarded.
	VerifyBeforeSend bool
}

// relayCounter tracks rolling send counts for one custom SMTP relay.
type relayCounter struct {
	minCount  int
	hourCount int
	dayCount  int
	minReset  time.Time
	hourReset time.Time
	dayReset  time.Time
}

// formatRelayLogMX is stored in email_logs.mx_host when mail was accepted by a custom relay.
// We intentionally omit the relay host/port/IP so internal infrastructure details are not
// exposed in user-visible log views.
func formatRelayLogMX(r SMTPRelay) string {
	label := strings.TrimSpace(r.Label)
	if label == "" {
		label = "custom smtp"
	}
	return "via relay: " + label
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
	// ipPoolMinDefer optional override when all IPs busy but no wait could be computed (0 = use tiny builtin fallback only).
	ipPoolMinDefer time.Duration
	dkimSigner *dkim.SignOptions
	OnEvent    func(DeliveryEvent) // optional hook for DB logging

	// DKIMKeyLoader optionally provides per-domain DKIM keys from the DB.
	DKIMKeyLoader func(domain string) (privKeyPEM, selector string, ok bool)

	// IPPoolProvider returns the active IP entries with per-IP rate limits.
	// Return nil or empty to use the system default IP.
	IPPoolProvider func() []IPEntry

	// IPPoolMasterProvider returns master limits for a domain. Applies to ALL IPs when no IP-specific domain rule exists.
	// Per-domain only: different rules for different domains. Returns found=false if no master rule for that domain.
	IPPoolMasterProvider func(domain string) (perMin, perHour, perDay, intervalSec int, found bool)

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

	// EmailVerifier verifies a single recipient address.
	// Returns (valid=true, reason="") when the address is deliverable.
	// Returns (valid=false, reason=<why>) for definitive failures (bad format, no MX, mailbox not found).
	// When nil, verification is skipped regardless of relay.VerifyBeforeSend.
	EmailVerifier func(email string) (valid bool, reason string)

	// SkipDomainChecker returns true when the recipient domain is on the admin skip list.
	// No SMTP handshake is attempted — recipients are immediately marked suppressed.
	SkipDomainChecker func(domain string) bool

	// SuppressionChecker returns true if the recipient has unsubscribed from this user's mail.
	SuppressionChecker func(username, email string) bool

	// UnsubBaseURL is the public base URL used to build List-Unsubscribe headers
	// (e.g. "https://mail.example.com"). Empty = feature disabled.
	UnsubBaseURL string

	// UnsubTokenFn generates a user-level HMAC token given a username.
	UnsubTokenFn func(username string) string

	// Per-user relay rotation and per-relay rate-limit counters (both guarded by userRelayMu).
	userRelayMu   sync.Mutex
	userRelayIdx  map[string]int
	relayCounters map[uint]*relayCounter

	// Per-domain 421 cooldown tracking.
	cooldownMu sync.Mutex
	cooldowns  map[string]*domainCooldownEntry

	// Per-MX-host connection semaphores (capacity from delivery.mx_max_concurrent, default 2).
	semMu sync.Mutex
	sems  map[string]chan struct{}

	// Per-(pool IP × recipient domain) SMTP slot tokens when delivery.per_outbound_ip_concurrent > 0.
	outIPTokMu  sync.Mutex
	outIPTokens map[string]chan struct{}
	ipSlotFair  uint64 // rotate blocking wait across pool IPs

	// IP pool rotation + per-IP rate limiting (all guarded by ipMu).
	ipMu       sync.Mutex
	ipIdx      int
	ipCounters map[string]*ipCounter

	// workCh feeds workers; a single dispatcher calls PopFairBatch to avoid
	// N workers hammering the queue mutex and re-reading every file per pop.
	workCh chan *queue.Message

	metrics *deliveryMetrics // live counters for admin monitoring

	traceMu      sync.Mutex
	activeTraces map[string]*deliveryTrace // messages currently in deliver()

	outboundMXPorts []string // per MX host, tried in order (default 25, 587)
	dialNetwork     string   // tcp4 or tcp

	// Domain dial-failure cache: when ALL MX hosts for a domain fail with
	// connection errors (timeout / refused), skip that domain for a few minutes
	// instead of burning 30s+ of worker time per message on each attempt.
	dialFailMu sync.Mutex
	dialFails  map[string]time.Time // domain → "do not dial until" time

	// Recipient dedup: prevents the same (user, recipient) pair from being
	// delivered more than once within a short window.  Catches duplicate queue
	// entries from bulk imports and avoids relay re-delivery when
	// system_and_custom mode uses the user's own server as relay.
	dedupMu   sync.Mutex
	dedupSeen map[string]time.Time // "username\x1eto" → last delivery time
}

// New creates a delivery Engine.
func New(cfg config.DeliveryConfig, q *queue.Queue) *Engine {
	e := &Engine{
		cfg:              cfg,
		queue:            q,
		cooldowns:        make(map[string]*domainCooldownEntry),
		sems:             make(map[string]chan struct{}),
		outIPTokens:      make(map[string]chan struct{}),
		ipCounters:       make(map[string]*ipCounter),
		userRelayIdx:     make(map[string]int),
		relayCounters:    make(map[uint]*relayCounter),
		throttleCounters: make(map[string]*throttleCounter),
		dialFails:        make(map[string]time.Time),
		dedupSeen:        make(map[string]time.Time),
		metrics:          newDeliveryMetrics(),
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

	e.outboundMXPorts = normalizeOutboundMXPorts(cfg.OutboundMXPorts)
	e.dialNetwork = normalizeOutboundDialNetwork(cfg.OutboundDialNetwork)
	log.Printf("delivery: outbound MX ports %v, dial network=%s, connect timeout=%v", e.outboundMXPorts, e.dialNetwork, e.connectTO)

	e.ipPoolMinDefer = 0
	s := strings.TrimSpace(cfg.IPPoolMinDefer)
	if s != "" && s != "0" {
		if d, err := time.ParseDuration(s); err == nil && d > 0 {
			e.ipPoolMinDefer = d
		} else if err != nil {
			log.Printf("delivery: invalid ip_pool_min_defer %q — ignoring (no extra defer delay)", s)
		}
	}

	if cfg.DKIM.Enabled {
		if opts, err := loadDKIMSigner(cfg.DKIM); err != nil {
			log.Printf("delivery: DKIM disabled — failed to load key: %v", err)
		} else {
			e.dkimSigner = opts
			log.Printf("delivery: DKIM enabled for domain=%s selector=%s", cfg.DKIM.Domain, cfg.DKIM.Selector)
		}
	}
	if od := strings.TrimSpace(cfg.OutboundDKIMDomain); od != "" {
		log.Printf("delivery: outbound_dkim_domain=%q — strip upstream DKIM-Signature, re-sign with this domain (Admin→Domains key, or config dkim if domain matches)", od)
	}

	return e
}

// logV prints only when VerboseLog is enabled (reduces terminal noise and I/O at high volume).
func (e *Engine) logV(format string, args ...interface{}) {
	if e.cfg.VerboseLog {
		log.Printf(format, args...)
	}
}

// finalizeIPPoolDeferWait preserves computed slot times from domain/IP intervals (no added seconds).
// Light jitter spreads worker wakeups; sub-50ms waits get a minimal floor against busy-spin.
func (e *Engine) finalizeIPPoolDeferWait(w time.Duration) time.Duration {
	if w < 0 {
		w = 0
	}
	if w > 0 && w < 50*time.Millisecond {
		w = 50 * time.Millisecond
	}
	w += time.Duration(mathrand.Intn(251)) * time.Millisecond // 0–250ms, not extra seconds
	return w
}

// Start launches a single queue dispatcher plus worker goroutines and returns immediately.
func (e *Engine) Start() {
	n := e.cfg.Workers
	if n < 1 {
		n = 1
	}
	buf := e.cfg.QueueChannelSize
	if buf <= 0 {
		buf = n * 4
		if buf < 64 {
			buf = 64
		}
	}
	const maxQueueBuf = 16000
	if buf > maxQueueBuf {
		buf = maxQueueBuf
	}
	e.workCh = make(chan *queue.Message, buf)
	e.startMetricsRotator()
	go e.dispatch()
	log.Printf("delivery: starting %d workers (per-user queue dirs, buffer=%d — typical in-flight ≤ workers+buffer, not a fixed 500 cap)", n, buf)
	for i := 0; i < n; i++ {
		go e.worker(i)
	}
	go e.logIPPoolStatus()
	go e.dedupCleaner()
}

// dispatch pulls batches from the file queue and fills workCh so workers never
// contend on the queue mutex (previously each worker called PopFair and scanned all files).
func (e *Engine) dispatch() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	capacity := cap(e.workCh)
	for {
		select {
		case <-e.queue.Ready():
		case <-ticker.C:
		}
		for {
			free := capacity - len(e.workCh)
			if free <= 0 {
				break
			}
			batch := e.queue.PopFairBatch(free)
			if len(batch) == 0 {
				break
			}
			for _, msg := range batch {
				e.workCh <- msg
			}
		}
	}
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
	log.Printf("[IPPOOL] Domain rules with “Min. interval (sec)” cap throughput per IP×domain (e.g. 30s ≈ 2 msgs/min to that domain from each IP).")
	if e.ipPoolMinDefer > 0 {
		log.Printf("[IPPOOL] Defer uses computed domain/IP slot times only (+ ≤250ms jitter). Rare unknown-wait fallback: %v (delivery.ip_pool_min_defer).", e.ipPoolMinDefer)
	} else {
		log.Printf("[IPPOOL] Defer uses computed domain/IP slot times only (+ ≤250ms jitter); no extra delay. IPs rotate; each IP×domain honors Min. interval (sec).")
	}
}

func zeroOrInt(n int) string {
	if n == 0 {
		return "∞"
	}
	return fmt.Sprintf("%d", n)
}

func (e *Engine) worker(id int) {
	for msg := range e.workCh {
		e.deliver(msg)
	}
}

func (e *Engine) deliver(msg *queue.Message) {
	e.RecordDeliveryAttempt()
	e.traceStart(msg)
	defer e.traceEnd(msg.ID)
	e.logV("[DELIVERY] ══════════════════════════════════════════")
	e.logV("[DELIVERY]   id      = %s", msg.ID)
	e.logV("[DELIVERY]   from    = %s", msg.From)
	e.logV("[DELIVERY]   to      = %v", msg.To)
	e.logV("[DELIVERY]   attempt = %d / %d", msg.RetryCount+1, e.cfg.MaxRetries+1)
	e.logV("[DELIVERY]   size    = %d bytes", len(msg.Data))

	e.tracePhase(msg.ID, "inject_headers", "")
	data := injectMissingHeaders(msg.Data, e.cfg.HeloName, msg.From)

	// ── Unsubscribe header injection ───────────────────────────────────────
	if e.UnsubBaseURL != "" && e.UnsubTokenFn != nil {
		token := e.UnsubTokenFn(msg.Username)
		unsubURL := e.UnsubBaseURL + "/unsub?t=" + token
		data = injectUnsubHeaders(data, unsubURL)
	}

	e.tracePhase(msg.ID, "suppression_check", "")
	// ── Suppression filter — skip opted-out recipients ─────────────────────
	if e.SuppressionChecker != nil {
		var active []string
		for _, rcpt := range msg.To {
			if e.SuppressionChecker(msg.Username, rcpt) {
				e.logV("[DELIVERY] ⏭ %s suppressed — skipping", rcpt)
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
			e.logV("[DELIVERY] ✓ message %s: all %d recipient(s) suppressed — done", msg.ID, len(msg.To))
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

	// ── Recipient deduplication ──────────────────────────────────────────
	// Prevent the same (user, recipient) pair from being delivered twice in a
	// short window.  Catches duplicate queue entries and relay re-delivery.
	{
		var unique []string
		for _, rcpt := range msg.To {
			if e.isRecentDuplicate(msg.Username, rcpt) {
				e.logV("[DELIVERY] ⏭ %s: duplicate — recently delivered for user %q, skipping", rcpt, msg.Username)
			} else {
				unique = append(unique, rcpt)
			}
		}
		if len(unique) == 0 {
			e.logV("[DELIVERY] ✓ message %s: all %d recipient(s) recently delivered — duplicate, completing", msg.ID, len(msg.To))
			e.queue.Complete(msg.ID)
			return
		}
		if len(unique) < len(msg.To) {
			filtered := *msg
			filtered.To = unique
			msg = &filtered
		}
	}

	// ── Custom SMTP relay routing ──────────────────────────────────────────
	// If a UserSMTPProvider is registered, check whether this user's messages
	// should be routed through a custom relay instead of direct MX delivery.
	if e.UserSMTPProvider != nil && msg.Username != "" {
		mode, relays := e.UserSMTPProvider(msg.Username)
		if mode == "custom_only" || mode == "system_and_custom" {
			relay, retryAfter := e.pickAvailableRelay(msg.Username, mode, relays)

			// All custom relays are at their send limit — defer the message.
			if relay == nil && retryAfter > 0 {
				e.logV("[DELIVERY] ⏳ message %s: all custom relays at send limit for %q — defer %v",
					msg.ID, msg.Username, retryAfter.Round(time.Second))
				e.queue.DeferNoIncrement(msg, retryAfter, "custom SMTP relay send limit reached")
				if e.OnEvent != nil {
					for _, to := range msg.To {
						e.OnEvent(DeliveryEvent{
							MessageID: msg.ID, Username: msg.Username,
							From: msg.From, To: to, Status: "deferred",
							Error: "custom SMTP relay send limit reached",
						})
					}
				}
				return
			}

		if relay != nil {
			e.tracePhase(msg.ID, "custom_relay", fmt.Sprintf("%s %s:%d", relay.Label, relay.Host, relay.Port))
			e.logV("[DELIVERY]   routing via custom relay %q (%s:%d)", relay.Label, relay.Host, relay.Port)

			// ── Verify-before-send via direct MX delivery ────────────────────
			// Problem: SMTP RCPT TO probes are unreliable for Yahoo/AOL/Gmail because
			// these providers return 250 for every RCPT TO (DHA protection).  The real
			// rejection (e.g. 552 mailbox not found) only arrives at DATA close.
			//
			// Solution: attempt actual direct delivery from our system IP to the
			// recipient's MX server — the same path used by direct MX delivery.
			// Our IP gets the real DATA-close response from Yahoo (552 = invalid).
			//
			//   • Delivered directly → record as "delivered", skip relay (no duplicate)
			//   • Hard bounce (552)  → record as "hard_bounce", suppress, skip relay
			//   • Can't connect / rate-limited → fall through to relay (relay as fallback)
			//
			// This only runs when relay.VerifyBeforeSend is enabled.
			activeRcpts := msg.To
			if relay.VerifyBeforeSend && len(msg.To) > 0 {
				e.tracePhase(msg.ID, "verify_before_send_direct", fmt.Sprintf("%d recipients", len(msg.To)))

				// Group recipients by domain so we make one MX connection per domain.
				byDomain := make(map[string][]string)
				for _, rcpt := range msg.To {
					parts := strings.SplitN(rcpt, "@", 2)
					if len(parts) == 2 {
						byDomain[strings.ToLower(parts[1])] = append(byDomain[strings.ToLower(parts[1])], rcpt)
					}
				}

				var needsRelay []string

				for domain, domRcpts := range byDomain {
					var hardBounced []string

					onBounce := func(rcpt, reason string) {
						hardBounced = append(hardBounced, rcpt)
						log.Printf("[DELIVERY] ⏭ verify-before-send: %s hard_bounce during direct probe (%s)", rcpt, reason)
						if e.OnEvent != nil {
							e.OnEvent(DeliveryEvent{
								MessageID: msg.ID, Username: msg.Username,
								From: msg.From, To: rcpt, Status: "hard_bounce",
								Error:  "verify-before-send direct: " + reason,
								MXHost: domain,
							})
						}
					}

					_, directErr := e.deliverToDomain(msg.From, domain, domRcpts, data, onBounce, msg.ID)
					if directErr == nil {
						// Direct delivery succeeded — record each non-bounced rcpt as delivered.
						bounced := make(map[string]bool)
						for _, b := range hardBounced {
							bounced[b] = true
						}
						for _, rcpt := range domRcpts {
							if !bounced[rcpt] {
								log.Printf("[DELIVERY] ✓ verify-before-send: %s delivered directly — skipping relay", rcpt)
								if e.OnEvent != nil {
									e.OnEvent(DeliveryEvent{
										MessageID: msg.ID, Username: msg.Username,
										From: msg.From, To: rcpt, Status: "delivered",
										MXHost: domain,
									})
								}
								e.recordDedup(msg.Username, rcpt)
							}
						}
					} else {
						// Could not deliver directly (blocked IP, rate-limited, etc.).
						// Fall through to the relay for non-bounced recipients.
						bounced := make(map[string]bool)
						for _, b := range hardBounced {
							bounced[b] = true
						}
						for _, rcpt := range domRcpts {
							if !bounced[rcpt] {
								needsRelay = append(needsRelay, rcpt)
							}
						}
						log.Printf("[DELIVERY]   verify-before-send: direct delivery to %s failed (%v) — using relay for %d recipient(s)",
							domain, directErr, len(needsRelay))
					}
				}

				if len(needsRelay) == 0 && len(activeRcpts) > 0 {
					e.logV("[DELIVERY] ✓ verify-before-send: all recipients handled by direct delivery — completing without relay")
					e.queue.Complete(msg.ID)
					return
				}
				activeRcpts = needsRelay
				e.logV("[DELIVERY]   verify-before-send: %d/%d recipients need relay (direct delivery not possible)",
					len(activeRcpts), len(msg.To))
			}
			// ── end verify-before-send ────────────────────────────────────────

			fromAddr := msg.From
			relayData := stripDKIMSignatureHeaders(data)
			if relay.FromAddress != "" {
				fromAddr = relay.FromAddress
				relayData = email.RewriteFromHeader(relayData, fromAddr)
			}
			if err := e.deliverViaRelay(*relay, fromAddr, activeRcpts, relayData, msg.ID); err != nil {
				log.Printf("[DELIVERY] ✗ relay %q failed: %v", relay.Label, err)
				if isPermanentSMTPError(err) {
					if e.OnEvent != nil {
						for _, to := range activeRcpts {
							e.OnEvent(DeliveryEvent{
								MessageID: msg.ID, Username: msg.Username,
								From: msg.From, To: to, Status: "hard_bounce",
								Error: err.Error(), MXHost: formatRelayLogMX(*relay),
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
						for _, to := range activeRcpts {
							e.OnEvent(DeliveryEvent{
								MessageID: msg.ID, Username: msg.Username,
								From: msg.From, To: to, Status: "deferred",
								Error: err.Error(), MXHost: formatRelayLogMX(*relay),
							})
						}
					}
				}
			} else {
				e.logV("[DELIVERY] ✓ message %s relayed via %q SUCCESSFULLY", msg.ID, relay.Label)
				e.queue.Complete(msg.ID)
				relayMX := formatRelayLogMX(*relay)
				for _, to := range activeRcpts {
					e.recordDedup(msg.Username, to)
					if e.OnEvent != nil {
						e.OnEvent(DeliveryEvent{
							MessageID: msg.ID, Username: msg.Username,
							From: msg.From, To: to, Status: "delivered",
							MXHost: relayMX,
						})
					}
				}
			}
			return
		}

			// relay == nil and retryAfter == 0:
			// system_and_custom selected the system slot → fall through.
			// custom_only with no relays configured → fail.
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
			// system_and_custom with system slot → fall through to system delivery.
		}
	}
	// ── end custom relay routing ───────────────────────────────────────────

	e.tracePhase(msg.ID, "dkim_resolve", "")
	// Resolve DKIM signer: optional fixed outbound domain (relay server), else From: domain, else config key.
	signer := e.resolveDKIMSigner(data)
	if signer != nil {
		data = stripDKIMSignatureHeaders(data)
		signed, err := signDKIM(data, signer)
		if err != nil {
			log.Printf("[DELIVERY] ⚠ DKIM sign failed (sending unsigned): %v", err)
		} else {
			data = signed
			e.logV("[DELIVERY]   DKIM signed ok (d=%s)", signer.Domain)
		}
	}

	e.tracePhase(msg.ID, "group_by_domain", fmt.Sprintf("%d recipients", len(msg.To)))
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
	// suppressedRcpts tracks recipients silently dropped (skip domain list, etc.).
	// These already have a "suppressed" log entry and must not be overwritten with "delivered".
	suppressedRcpts := make(map[string]bool)

	if len(byDomain) == 0 {
		e.tracePhase(msg.ID, "no_valid_domains", "all recipients skipped or invalid")
	}

	for domain, rcpts := range byDomain {
		e.traceDomain(msg.ID, domain)
		e.tracePhase(msg.ID, "domain_round", fmt.Sprintf("%s (%d rcpt)", domain, len(rcpts)))
		e.logV("[DELIVERY]   delivering to domain %q (%v)", domain, rcpts)

		// ── Admin domain skip list — no handshake, no MX lookup ──────────────
		if e.SkipDomainChecker != nil && e.SkipDomainChecker(domain) {
			e.logV("[DELIVERY] ⏭ domain %q is on skip list — silently skipping %d recipient(s)", domain, len(rcpts))
			for _, rcpt := range rcpts {
				suppressedRcpts[rcpt] = true
			}
			if e.OnEvent != nil {
				for _, rcpt := range rcpts {
					e.OnEvent(DeliveryEvent{
						MessageID: msg.ID, Username: msg.Username,
						From: msg.From, To: rcpt, Status: "suppressed",
						Error: "domain is on admin skip list",
					})
				}
			}
			continue
		}

		// ── Per-user throttle check ───────────────────────────────────────────
		if reason, retryAfter := e.checkThrottle(msg.Username, domain, true); reason != "" {
			e.tracePhase(msg.ID, "user_throttle_block", fmt.Sprintf("%s defer_in=%v", reason, retryAfter.Round(time.Second)))
			e.logV("[DELIVERY] ⏳ %s", reason)
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

		mxHost, err := e.deliverToDomain(msg.From, domain, rcpts, data, onRcptBounce, msg.ID)

		// IP pool exhausted — instead of deferring to disk immediately,
		// sleep in-memory for the computed wait (typically a few seconds)
		// then retry once. Avoids costly disk write→read→parse round-trip.
		if err != nil && isIPPoolLimited(err) {
			var poolErr *ipPoolLimitedError
			errors.As(err, &poolErr)
			wait := poolErr.waitFor
			if wait > 0 && wait <= 25*time.Second {
				e.logV("[IPPOOL] ⏳ message %s: all IPs busy for %s — sleeping %v then retrying in-memory", msg.ID, domain, wait)
				time.Sleep(wait)
				mxHost, err = e.deliverToDomain(msg.From, domain, rcpts, data, onRcptBounce, msg.ID)
			}
		}

		if err != nil {
			e.logV("[DELIVERY] ✗ domain %q failed: %v", domain, err)

			// IP pool still exhausted after in-memory retry — defer to disk.
			if isIPPoolLimited(err) {
				var poolErr *ipPoolLimitedError
				errors.As(err, &poolErr)
				wait := poolErr.waitFor
				e.logV("[IPPOOL] ⏳ message %s queued — waiting %v for an IP slot", msg.ID, wait)
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

			// Domain dial-failure cached — defer without burning a retry slot.
			if isDomainDialCached(err) {
				var dErr *domainDialCachedError
				errors.As(err, &dErr)
				e.queue.DeferNoIncrement(msg, dErr.waitFor, err.Error())
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
				e.logV("[DELIVERY] ✗ hard bounce for domain %q", domain)
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
			} else if isTempRateLimitError(err) || strings.Contains(err.Error(), "rate-limited") {
				e.logV("[DELIVERY] ⏳ domain %q is rate-limited — will defer (retries not consumed)", domain)
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
		// Count recipients that were actually delivered (not hard-bounced or suppressed).
		deliveredRcpts := 0
		for _, to := range msg.To {
			if !hardBouncedRcpts[to] && !suppressedRcpts[to] {
				deliveredRcpts++
			}
		}

		if deliveredRcpts > 0 {
			e.logV("[DELIVERY] ✓ message %s DELIVERED SUCCESSFULLY (%d/%d recipients)",
				msg.ID, deliveredRcpts, len(msg.To))
		} else {
			log.Printf("[DELIVERY] ✗ message %s — all %d recipient(s) hard-bounced or suppressed, removing from queue",
				msg.ID, len(msg.To))
		}

		// Remove from queue regardless — all recipients are definitively handled.
		e.queue.Complete(msg.ID)

		for _, to := range msg.To {
			if hardBouncedRcpts[to] || suppressedRcpts[to] {
				continue
			}
			e.recordDedup(msg.Username, to)
			if e.OnEvent != nil {
				e.OnEvent(DeliveryEvent{
					MessageID: msg.ID, Username: msg.Username,
					From: msg.From, To: to, Status: "delivered",
					MXHost: recipientMX[to],
				})
			}
		}
		return
	}

	// If the failure is purely a 421 rate-limit, defer matching the domain cooldown
	// without consuming a retry slot so MaxRetries is reserved for real failures.
	isRateLimit := isTempRateLimitError(lastErr) || strings.Contains(lastErr.Error(), "rate-limited")
	if isRateLimit {
		// Parse the remaining cooldown from the domain cache (if it exists),
		// otherwise use a short default. Previously was a hardcoded 35min
		// which stacked on top of the domain cooldown and was way too long.
		backoff := 2*time.Minute + 30*time.Second
		for domain := range byDomain {
			if until := e.domainCooldownUntil(domain); !until.IsZero() {
				if rem := time.Until(until); rem > backoff {
					backoff = rem + 15*time.Second
				}
			}
		}
		if backoff > 16*time.Minute {
			backoff = 16 * time.Minute
		}
		e.logV("[DELIVERY] ⏳ message %s DEFERRED (rate-limited) — retry in %v (retries NOT consumed)",
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
		e.logV("[DELIVERY] ✗ message %s PERMANENTLY FAILED (max retries reached)", msg.ID)
		e.logV("[DELIVERY]   reason: %v", lastErr)
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
	e.logV("[DELIVERY] ⏳ message %s DEFERRED — retry in %v (attempt %d next)",
		msg.ID, backoff, msg.RetryCount+2)
	e.logV("[DELIVERY]   reason: %v", lastErr)
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

func normalizeOutboundMXPorts(in []string) []string {
	var out []string
	for _, p := range in {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		// MTA-to-MTA is almost always port 25. Trying 587 second often doubles connect_timeout
		// on Yahoo/AOL/ATT (*.yahoodns.net) and similar MX where 587 may blackhole or stall.
		// Set delivery.outbound_mx_ports: ["25","587"] (or ["587","25"]) if your host blocks 25.
		return []string{"25"}
	}
	return out
}

func normalizeOutboundDialNetwork(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "tcp", "tcp6":
		return "tcp"
	case "tcp4", "":
		return "tcp4"
	default:
		log.Printf("delivery: unknown outbound_dial_network %q — using tcp4", s)
		return "tcp4"
	}
}

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
// First hit: 2 min cooldown. Each consecutive hit grows: 2m → 4m → 8m → 15m (cap).
// Previous 15m → 30m → 60m was far too aggressive and blocked ALL messages to
// Yahoo/AOL for 15+ minutes after a single 421.
func (e *Engine) recordRateLimit(domain string) time.Duration {
	e.cooldownMu.Lock()
	defer e.cooldownMu.Unlock()
	c, ok := e.cooldowns[domain]
	if !ok {
		c = &domainCooldownEntry{}
		e.cooldowns[domain] = c
	}
	c.streak++
	backoff := time.Duration(2) * time.Minute * (1 << uint(c.streak-1)) // 2m, 4m, 8m, 16m...
	if backoff > 15*time.Minute {
		backoff = 15 * time.Minute
	}
	c.until = time.Now().Add(backoff)
	e.logV("[DELIVERY] ⏳ domain %q rate-limited (421) — cooldown %v until %s (streak=%d)",
		domain, backoff, c.until.Format("15:04:05"), c.streak)
	return backoff
}

// clearCooldown resets the rate-limit streak for a domain after a success.
func (e *Engine) clearCooldown(domain string) {
	e.cooldownMu.Lock()
	defer e.cooldownMu.Unlock()
	delete(e.cooldowns, domain)
}

// ── Domain dial-failure cache ────────────────────────────────────────────────
// After ALL MX hosts for a domain fail with TCP dial errors (connection
// refused or i/o timeout), we cache the failure for a few minutes.  Next
// messages to the same domain are immediately deferred without consuming
// 30s+ of worker time per MX attempt.

type domainDialCachedError struct {
	domain  string
	waitFor time.Duration
}

func (e *domainDialCachedError) Error() string {
	return fmt.Sprintf("domain %s: all MX dial failures cached — skip %v", e.domain, e.waitFor.Round(time.Second))
}

func isDomainDialCached(err error) bool {
	var e *domainDialCachedError
	return errors.As(err, &e)
}

// isDomainDialBlocked checks if the domain is in the connection-failure cache.
func (e *Engine) isDomainDialBlocked(domain string) (bool, time.Duration) {
	e.dialFailMu.Lock()
	defer e.dialFailMu.Unlock()
	t, ok := e.dialFails[domain]
	if !ok {
		return false, 0
	}
	rem := time.Until(t)
	if rem <= 0 {
		delete(e.dialFails, domain)
		return false, 0
	}
	return true, rem
}

func (e *Engine) recordDomainDialFail(domain string, dur time.Duration) {
	e.dialFailMu.Lock()
	defer e.dialFailMu.Unlock()
	e.dialFails[domain] = time.Now().Add(dur)
	log.Printf("[DELIVERY] domain %q: all MX servers unreachable — caching failure for %v", domain, dur)
}

func (e *Engine) clearDomainDialFail(domain string) {
	e.dialFailMu.Lock()
	defer e.dialFailMu.Unlock()
	delete(e.dialFails, domain)
}

// ── Recipient deduplication ──────────────────────────────────────────────

const dedupWindow = 1 * time.Minute

func (e *Engine) isRecentDuplicate(username, to string) bool {
	key := strings.ToLower(username) + "\x1e" + strings.ToLower(to)
	e.dedupMu.Lock()
	defer e.dedupMu.Unlock()
	t, ok := e.dedupSeen[key]
	return ok && time.Since(t) < dedupWindow
}

func (e *Engine) recordDedup(username, to string) {
	key := strings.ToLower(username) + "\x1e" + strings.ToLower(to)
	e.dedupMu.Lock()
	e.dedupSeen[key] = time.Now()
	e.dedupMu.Unlock()
}

func (e *Engine) dedupCleaner() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		e.dedupMu.Lock()
		now := time.Now()
		for k, t := range e.dedupSeen {
			if now.Sub(t) > dedupWindow {
				delete(e.dedupSeen, k)
			}
		}
		e.dedupMu.Unlock()
	}
}

// isDialError returns true if the error is a TCP dial failure (not an SMTP error).
func isDialError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "dial ") && (strings.Contains(s, "timeout") ||
		strings.Contains(s, "connection refused") ||
		strings.Contains(s, "no route") ||
		strings.Contains(s, "network is unreachable") ||
		strings.Contains(s, "i/o timeout"))
}

// mxSlotCap returns the per-MX-host concurrency limit (shared across all workers and source IPs).
func (e *Engine) mxSlotCap() int {
	n := e.cfg.MXMaxConcurrent
	if n < 1 {
		n = 2
	}
	if e.usePerOutboundPipeline() {
		pool := e.IPPoolProvider()
		need := len(pool) * e.perOutboundSMTPConnsPerIP()
		if need > n {
			n = need
		}
	}
	const hardMax = 32
	if n > hardMax {
		return hardMax
	}
	return n
}

// perOutboundSMTPConnsPerIP is 0 when the per-(IP×domain) pipeline feature is off.
func (e *Engine) perOutboundSMTPConnsPerIP() int {
	n := e.cfg.PerOutboundIPConcurrent
	if n < 1 {
		return 0
	}
	const hardMax = 16
	if n > hardMax {
		return hardMax
	}
	return n
}

func (e *Engine) usePerOutboundPipeline() bool {
	if e.perOutboundSMTPConnsPerIP() < 1 || e.IPPoolProvider == nil {
		return false
	}
	return len(e.IPPoolProvider()) > 0
}

// acquireMXSlot blocks until a connection slot is available for the MX host.
func (e *Engine) acquireMXSlot(mxHost string) {
	capacity := e.mxSlotCap()
	e.semMu.Lock()
	sem, ok := e.sems[mxHost]
	if !ok {
		sem = make(chan struct{}, capacity)
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

// outboundIPTokMapKey identifies one concurrency bucket: outbound pool IP + recipient domain (e.g. gmail.com).
func outboundIPTokMapKey(ip, rcptDomain string) string {
	return ip + "\x1e" + strings.ToLower(strings.TrimSpace(rcptDomain))
}

// outboundIPTokChan returns the token channel for (pool IP × recipient domain): N tokens = up to N concurrent
// SMTP sessions from that IP to that domain only. Other domains for the same IP use different channels.
func (e *Engine) outboundIPTokChan(ip, rcptDomain string) chan struct{} {
	capN := e.perOutboundSMTPConnsPerIP()
	key := outboundIPTokMapKey(ip, rcptDomain)
	e.outIPTokMu.Lock()
	defer e.outIPTokMu.Unlock()
	ch, ok := e.outIPTokens[key]
	if !ok {
		ch = make(chan struct{}, capN)
		for i := 0; i < capN; i++ {
			ch <- struct{}{}
		}
		e.outIPTokens[key] = ch
	}
	return ch
}

func (e *Engine) tryTakeOutboundIPTok(ip, rcptDomain string) bool {
	select {
	case <-e.outboundIPTokChan(ip, rcptDomain):
		return true
	default:
		return false
	}
}

func (e *Engine) takeOutboundIPTokBlocking(traceID, ip, rcptDomain string) {
	e.tracePhase(traceID, "waiting_outbound_ip_slot", fmt.Sprintf("%s → %s", ip, strings.ToLower(strings.TrimSpace(rcptDomain))))
	<-e.outboundIPTokChan(ip, rcptDomain)
}

func (e *Engine) returnOutboundIPTok(ip, rcptDomain string) {
	select {
	case e.outboundIPTokChan(ip, rcptDomain) <- struct{}{}:
	default:
		log.Printf("[IPPOOL] ⚠ outbound IP×domain token imbalance for %s → %s", ip, rcptDomain)
	}
}

// deliverToDomain attempts delivery to a domain, returning the successful MX host on success.
// onRcptBounce is called for each recipient that receives a permanent 5xx during RCPT TO.
// Those recipients are skipped from DATA; the remaining valid recipients are delivered.
func (e *Engine) deliverToDomain(from, domain string, rcpts []string, data []byte,
	onRcptBounce func(rcpt, reason string), traceID string) (string, error) {
	// Check dial-failure cache — domain known to be unreachable.
	if blocked, rem := e.isDomainDialBlocked(domain); blocked {
		e.tracePhase(traceID, "domain_dial_cached", fmt.Sprintf("%s blocked ~%v", domain, rem.Round(time.Second)))
		e.logV("[DELIVERY] ⏭ domain %q dial-fail cached — skipping for %v", domain, rem.Round(time.Second))
		return "", &domainDialCachedError{domain: domain, waitFor: rem}
	}

	// Check per-domain 421 cooldown before doing anything.
	if until := e.domainCooldownUntil(domain); !until.IsZero() && time.Now().Before(until) {
		wait := time.Until(until).Round(time.Second)
		e.tracePhase(traceID, "domain_421_cooldown", fmt.Sprintf("%s blocked ~%v", domain, wait))
		e.logV("[DELIVERY] ⏳ domain %q is rate-limited — skipping for %v", domain, wait)
		return "", fmt.Errorf("domain rate-limited (421 cooldown), retry after %v", wait)
	}

	e.tracePhase(traceID, "mx_dns_lookup", domain)
	e.logV("[DELIVERY]   DNS MX lookup for %q", domain)
	mxRecords, err := lookupMX(domain)
	if err != nil {
		log.Printf("[DELIVERY] ✗ MX lookup failed for %q: %v", domain, err)
		return "", fmt.Errorf("MX lookup: %w", err)
	}

	e.logV("[DELIVERY]   MX records for %q:", domain)
	for _, mx := range mxRecords {
		e.logV("[DELIVERY]     pref=%d  host=%s", mx.Pref, mx.Host)
	}

	var lastMXErr error
	allRateLimited := true
	allDialErrors := true // track whether EVERY failure was a TCP dial error
	hadDialTimeout := false // first MX timed out → use shorter timeout for rest

	for _, mx := range mxRecords {
		for _, port := range e.outboundMXPorts {
			e.logV("[DELIVERY]   trying MX %s port=%s (pref=%d)", mx.Host, port, mx.Pref)

			// After the first dial timeout, use a shorter timeout for remaining MX
			// hosts. If port 25 is blocked at the network level, ALL hosts will
			// timeout — no need to burn 30s per host.
			connectTO := e.connectTO
			if hadDialTimeout {
				connectTO = 10 * time.Second
				if connectTO > e.connectTO {
					connectTO = e.connectTO
				}
			}

			// Respect per-MX connection limit (blocks when all slots to same MX host are in use).
			e.tracePhase(traceID, "waiting_mx_semaphore", fmt.Sprintf("%s:%s (max %d concurrent)", mx.Host, port, e.mxSlotCap()))
			e.acquireMXSlot(mx.Host)
			e.tracePhase(traceID, "smtp_connect_send", fmt.Sprintf("%s:%s", mx.Host, port))
			mxErr := e.sendToMX(from, domain, mx.Host, port, rcpts, data, onRcptBounce, traceID, connectTO)
			e.releaseMXSlot(mx.Host)

			if mxErr == nil {
				e.logV("[DELIVERY] ✓ delivered via MX %s:%s", mx.Host, port)
				e.clearCooldown(domain)
				e.clearDomainDialFail(domain)
				return mx.Host, nil
			}
			e.logV("[DELIVERY] ✗ MX %s:%s failed: %v", mx.Host, port, mxErr)

			// Track dial errors for the cache.
			if isDialError(mxErr) {
				if strings.Contains(mxErr.Error(), "timeout") {
					hadDialTimeout = true
				}
			} else {
				allDialErrors = false
			}

			// IP pool limited — all our outbound IPs are at capacity.
			// Return immediately; no point trying other MX hosts.
			if isIPPoolLimited(mxErr) {
				return "", mxErr
			}

			if isPermanentSMTPError(mxErr) {
				e.logV("[DELIVERY] ✗ permanent 5xx from %s — stopping MX attempts for %q", mx.Host, domain)
				return "", mxErr
			}

			if isTempRateLimitError(mxErr) {
				lastMXErr = mxErr
			} else {
				allRateLimited = false
				lastMXErr = mxErr
			}
		}
	}

	// If every MX attempt was a dial error (connection refused / timeout),
	// cache the failure so subsequent messages to this domain skip immediately.
	if allDialErrors && lastMXErr != nil && !allRateLimited {
		e.recordDomainDialFail(domain, 3*time.Minute)
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

// ipPoolMasterSnap holds master IP-pool limits for one recipient domain without calling the DB.
// Used so ipMu is never held across IPPoolMasterProvider / heavy work.
type ipPoolMasterSnap struct {
	perMin, perHour, perDay, intervalSec int
	found                                bool
}

func (e *Engine) snapshotIPPoolMaster(domain string) ipPoolMasterSnap {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if e.IPPoolMasterProvider == nil {
		return ipPoolMasterSnap{}
	}
	pm, ph, pd, iv, found := e.IPPoolMasterProvider(domain)
	if !found {
		return ipPoolMasterSnap{}
	}
	return ipPoolMasterSnap{pm, ph, pd, iv, true}
}

// ipEffectiveLimitsWithMaster resolves limits without calling IPPoolMasterProvider (use under ipMu).
func (e *Engine) ipEffectiveLimitsWithMaster(entry *IPEntry, domain string, master ipPoolMasterSnap) (perMin, perHour, perDay, intervalSec int) {
	domain = strings.ToLower(strings.TrimSpace(domain))
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
	if master.found {
		return master.perMin, master.perHour, master.perDay, master.intervalSec
	}
	return entry.PerMin, entry.PerHour, entry.PerDay, entry.IntervalSec
}

// ipEffectiveLimits returns per-min/hour/day and interval for one outbound IP sending to recipient domain `domain`.
// Priority: 1) Per-IP domain rule (exact match on domain), 2) Global master domain rule, 3) IP pool entry defaults.
// Prefer snapshotIPPoolMaster + ipEffectiveLimitsWithMaster on hot paths to avoid DB under ipMu.
func (e *Engine) ipEffectiveLimits(entry *IPEntry, domain string) (perMin, perHour, perDay, intervalSec int) {
	return e.ipEffectiveLimitsWithMaster(entry, domain, e.snapshotIPPoolMaster(domain))
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

	domain = strings.ToLower(domain)
	master := e.snapshotIPPoolMaster(domain)

	e.ipMu.Lock()
	defer e.ipMu.Unlock()

	now := time.Now()
	n := len(entries)

	for i := 0; i < n; i++ {
		entry := entries[(e.ipIdx+i)%n]
		perMin, perHour, perDay, intervalSec := e.ipEffectiveLimitsWithMaster(&entry, domain, master)

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
				e.logV("[IPPOOL]   IP %s: interval %ds not met for %s (wait %v)", entry.IP, intervalSec, domain, wait.Round(time.Second))
				continue
			}
		}

		if perMin > 0 && c.minCount >= perMin {
			e.logV("[IPPOOL]   IP %s: per-min limit %d reached for %s, skipping", entry.IP, perMin, domain)
			continue
		}
		if perHour > 0 && c.hourCount >= perHour {
			e.logV("[IPPOOL]   IP %s: per-hour limit %d reached for %s, skipping", entry.IP, perHour, domain)
			continue
		}
		if effectivePerDay > 0 && c.dayCount >= effectivePerDay {
			e.logV("[IPPOOL]   IP %s: per-day limit %d reached for %s, skipping", entry.IP, effectivePerDay, domain)
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
	foundWait := false
	for i := range entries {
		entry := &entries[i]
		perMin, perHour, perDay, intervalSec := e.ipEffectiveLimitsWithMaster(entry, domain, master)
		counterKey := entry.IP + "|" + domain
		c, ok := e.ipCounters[counterKey]
		if !ok {
			// First loop always creates counters; keep scanning other IPs.
			continue
		}
		if intervalSec > 0 && !c.lastSendAt.IsZero() {
			elapsed := time.Since(c.lastSendAt).Seconds()
			if elapsed < float64(intervalSec) {
				w := time.Duration(intervalSec)*time.Second - time.Duration(elapsed*float64(time.Second))
				if w > 0 {
					foundWait = true
					if w < minWait {
						minWait = w
					}
				}
			}
		}
		if perMin > 0 && c.minCount >= perMin {
			if w := time.Until(c.minReset); w > 0 {
				foundWait = true
				if w < minWait {
					minWait = w
				}
			}
		}
		if perHour > 0 && c.hourCount >= perHour {
			if w := time.Until(c.hourReset); w > 0 {
				foundWait = true
				if w < minWait {
					minWait = w
				}
			}
		}
		if perDay > 0 && c.dayCount >= perDay {
			if w := time.Until(c.dayReset); w > 0 {
				foundWait = true
				if w < minWait {
					minWait = w
				}
			}
		}
	}
	if !foundWait || minWait <= 0 {
		if e.ipPoolMinDefer > 0 {
			minWait = e.ipPoolMinDefer
		} else {
			minWait = 250 * time.Millisecond // rare path only; avoids hot loop without adding seconds
		}
	}
	minWait = e.finalizeIPPoolDeferWait(minWait)
	e.logV("[IPPOOL] ⏳ all pool IPs rate-limited — defer ~%v (slot from domain/IP limits + small jitter)",
		minWait.Round(time.Millisecond))
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

// getOrRollIPCounterUnderLock returns the rolling counter for ip|domain (e.ipMu held).
func (e *Engine) getOrRollIPCounterUnderLock(ip, domain string, now time.Time) *ipCounter {
	key := ip + "|" + domain
	c, ok := e.ipCounters[key]
	if !ok {
		c = &ipCounter{
			minReset:  now.Add(time.Minute),
			hourReset: now.Add(time.Hour),
			dayReset:  now.Add(24 * time.Hour),
		}
		e.ipCounters[key] = c
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
	return c
}

// ipDomainSendAllowedUnderLock is true if this IP may send to domain now (e.ipMu held; does not consume a slot).
func (e *Engine) ipDomainSendAllowedUnderLock(entry *IPEntry, domain string, now time.Time, master ipPoolMasterSnap) bool {
	domain = strings.ToLower(domain)
	c := e.getOrRollIPCounterUnderLock(entry.IP, domain, now)
	perMin, perHour, perDay, intervalSec := e.ipEffectiveLimitsWithMaster(entry, domain, master)

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
			return false
		}
	}
	if perMin > 0 && c.minCount >= perMin {
		return false
	}
	if perHour > 0 && c.hourCount >= perHour {
		return false
	}
	if effectivePerDay > 0 && c.dayCount >= effectivePerDay {
		return false
	}
	return true
}

// reserveOutboundIPDomainUnderLock consumes one rate slot and advances ipIdx (e.ipMu held).
func (e *Engine) reserveOutboundIPDomainUnderLock(entry *IPEntry, domain string, now time.Time, rotateOffset, poolLen int) {
	domain = strings.ToLower(domain)
	c := e.getOrRollIPCounterUnderLock(entry.IP, domain, now)
	c.minCount++
	c.hourCount++
	c.dayCount++
	c.lastSendAt = now
	e.ipIdx = (e.ipIdx + rotateOffset + 1) % poolLen
}

// ipPoolLimitedErrWhenAllBusy computes defer duration when every IP is over limits (e.ipMu held).
func (e *Engine) ipPoolLimitedErrWhenAllBusy(entries []IPEntry, domain string, now time.Time, master ipPoolMasterSnap) error {
	domain = strings.ToLower(domain)
	minWait := 24 * time.Hour
	foundWait := false
	for i := range entries {
		entry := &entries[i]
		perMin, perHour, perDay, intervalSec := e.ipEffectiveLimitsWithMaster(entry, domain, master)
		counterKey := entry.IP + "|" + domain
		c, ok := e.ipCounters[counterKey]
		if !ok {
			continue
		}
		if intervalSec > 0 && !c.lastSendAt.IsZero() {
			elapsed := time.Since(c.lastSendAt).Seconds()
			if elapsed < float64(intervalSec) {
				w := time.Duration(intervalSec)*time.Second - time.Duration(elapsed*float64(time.Second))
				if w > 0 {
					foundWait = true
					if w < minWait {
						minWait = w
					}
				}
			}
		}
		if perMin > 0 && c.minCount >= perMin {
			if w := time.Until(c.minReset); w > 0 {
				foundWait = true
				if w < minWait {
					minWait = w
				}
			}
		}
		if perHour > 0 && c.hourCount >= perHour {
			if w := time.Until(c.hourReset); w > 0 {
				foundWait = true
				if w < minWait {
					minWait = w
				}
			}
		}
		if perDay > 0 && c.dayCount >= perDay {
			if w := time.Until(c.dayReset); w > 0 {
				foundWait = true
				if w < minWait {
					minWait = w
				}
			}
		}
	}
	if !foundWait || minWait <= 0 {
		if e.ipPoolMinDefer > 0 {
			minWait = e.ipPoolMinDefer
		} else {
			minWait = 250 * time.Millisecond
		}
	}
	minWait = e.finalizeIPPoolDeferWait(minWait)
	e.logV("[IPPOOL] ⏳ all pool IPs rate-limited — defer ~%v (slot from domain/IP limits + small jitter)",
		minWait.Round(time.Millisecond))
	return &ipPoolLimitedError{waitFor: minWait}
}

// claimOutboundIPForSMTP takes a (pool IP × recipient domain) SMTP slot, then reserves IP-pool rate limits for that domain.
func (e *Engine) claimOutboundIPForSMTP(domain string, traceID string) (ip, hostname string, release func(), err error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	type cand struct {
		ent IPEntry
		off int
	}
outer:
	for {
		if e.IPPoolProvider == nil {
			return "", "", nil, nil
		}
		entries := e.IPPoolProvider()
		n := len(entries)
		if n == 0 {
			return "", "", nil, nil
		}
		master := e.snapshotIPPoolMaster(domain)

		e.ipMu.Lock()
		now := time.Now()
		var cands []cand
		for i := 0; i < n; i++ {
			ent := entries[(e.ipIdx+i)%n]
			if e.ipDomainSendAllowedUnderLock(&ent, domain, now, master) {
				cands = append(cands, cand{ent, i})
			}
		}
		if len(cands) == 0 {
			err := e.ipPoolLimitedErrWhenAllBusy(entries, domain, now, master)
			e.ipMu.Unlock()
			return "", "", nil, err
		}
		e.ipMu.Unlock()

		for _, ci := range cands {
			if !e.tryTakeOutboundIPTok(ci.ent.IP, domain) {
				continue
			}
			e.ipMu.Lock()
			now = time.Now()
			if !e.ipDomainSendAllowedUnderLock(&ci.ent, domain, now, master) {
				e.returnOutboundIPTok(ci.ent.IP, domain)
				e.ipMu.Unlock()
				continue outer
			}
			e.reserveOutboundIPDomainUnderLock(&ci.ent, domain, now, ci.off, n)
			ip := ci.ent.IP
			host := ci.ent.Hostname
			e.ipMu.Unlock()
			d := domain
			var once sync.Once
			release = func() {
				once.Do(func() { e.returnOutboundIPTok(ip, d) })
			}
			return ip, host, release, nil
		}

		fi := int(atomic.AddUint64(&e.ipSlotFair, 1)) % len(cands)
		ci := cands[fi]
		e.takeOutboundIPTokBlocking(traceID, ci.ent.IP, domain)
		e.ipMu.Lock()
		now = time.Now()
		if !e.ipDomainSendAllowedUnderLock(&ci.ent, domain, now, master) {
			e.returnOutboundIPTok(ci.ent.IP, domain)
			e.ipMu.Unlock()
			continue outer
		}
		e.reserveOutboundIPDomainUnderLock(&ci.ent, domain, now, ci.off, n)
		ip := ci.ent.IP
		host := ci.ent.Hostname
		e.ipMu.Unlock()
		d := domain
		var once sync.Once
		release = func() {
			once.Do(func() { e.returnOutboundIPTok(ip, d) })
		}
		return ip, host, release, nil
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

// pickAvailableRelay selects the next relay for a user using round-robin, respecting per-relay
// sending limits. Returns:
//   (relay != nil, 0)     — use this relay (counter already consumed)
//   (nil, 0)              — use system MX delivery (system_and_custom system slot selected, or no relays)
//   (nil, retryAfter > 0) — all custom relays are at their send limit; defer the message
func (e *Engine) pickAvailableRelay(username, mode string, relays []SMTPRelay) (*SMTPRelay, time.Duration) {
	if len(relays) == 0 {
		return nil, 0
	}

	e.userRelayMu.Lock()
	defer e.userRelayMu.Unlock()

	systemSlot := mode == "system_and_custom"
	poolSize := len(relays)
	if systemSlot {
		poolSize++ // slot 0 = system delivery (no limit)
	}

	startIdx := e.userRelayIdx[username] % poolSize
	var minRetry time.Duration

	for i := 0; i < poolSize; i++ {
		idx := (startIdx + i) % poolSize

		// System delivery slot (system_and_custom only) — always available.
		if systemSlot && idx == 0 {
			e.userRelayIdx[username] = (idx + 1) % poolSize
			return nil, 0
		}

		relayIdx := idx
		if systemSlot {
			relayIdx = idx - 1
		}
		if relayIdx < 0 || relayIdx >= len(relays) {
			continue
		}
		r := relays[relayIdx]

		// No limits set — always pick this relay.
		if r.LimitPerMin == 0 && r.LimitPerHour == 0 && r.LimitPerDay == 0 {
			e.userRelayIdx[username] = (idx + 1) % poolSize
			return &r, 0
		}

		// Check per-relay rate limits.
		now := time.Now()
		c, ok := e.relayCounters[r.ID]
		if !ok {
			c = &relayCounter{
				minReset:  now.Add(time.Minute),
				hourReset: now.Add(time.Hour),
				dayReset:  now.Add(24 * time.Hour),
			}
			e.relayCounters[r.ID] = c
		}
		if now.After(c.minReset)  { c.minCount = 0;  c.minReset  = now.Add(time.Minute) }
		if now.After(c.hourReset) { c.hourCount = 0; c.hourReset = now.Add(time.Hour) }
		if now.After(c.dayReset)  { c.dayCount = 0;  c.dayReset  = now.Add(24 * time.Hour) }

		if r.LimitPerMin > 0 && c.minCount >= r.LimitPerMin {
			if w := time.Until(c.minReset); w > 0 && (minRetry == 0 || w < minRetry) {
				minRetry = w
			}
			continue
		}
		if r.LimitPerHour > 0 && c.hourCount >= r.LimitPerHour {
			if w := time.Until(c.hourReset); w > 0 && (minRetry == 0 || w < minRetry) {
				minRetry = w
			}
			continue
		}
		if r.LimitPerDay > 0 && c.dayCount >= r.LimitPerDay {
			if w := time.Until(c.dayReset); w > 0 && (minRetry == 0 || w < minRetry) {
				minRetry = w
			}
			continue
		}

		// Within limits — consume a slot and return this relay.
		c.minCount++
		c.hourCount++
		c.dayCount++
		e.userRelayIdx[username] = (idx + 1) % poolSize
		return &r, 0
	}

	// All custom relays are at their send limit.
	if minRetry == 0 {
		minRetry = time.Minute
	}
	return nil, minRetry
}

// deliverViaRelay sends all recipients of a message through an authenticated SMTP relay.
func (e *Engine) deliverViaRelay(relay SMTPRelay, from string, rcpts []string, data []byte, traceID string) error {
	addr := fmt.Sprintf("%s:%d", relay.Host, relay.Port)
	tlsMode := strings.TrimSpace(relay.TLSMode)
	if tlsMode == "" {
		tlsMode = "auto"
	}
	e.tracePhase(traceID, "relay_tcp_dial", addr)
	e.logV("[DELIVERY]   relay connecting to %s (TLS: %s) …", addr, tlsMode)

	heloName := e.cfg.HeloName
	if heloName == "" {
		heloName = "localhost"
	}

	client, err := smtprelay.DialAndAuthenticate(smtprelay.Config{
		Host: relay.Host, Port: relay.Port,
		Username: relay.Username, Password: relay.Password, TLSMode: tlsMode,
		DialTimeout: e.connectTO, Helo: heloName, Logf: e.logV, MinTLSVersion: tls.VersionTLS12,
	})
	if err != nil {
		return fmt.Errorf("relay %s: %w", addr, err)
	}
	defer client.Close()
	e.tracePhase(traceID, "relay_smtp_mail_rcpt", addr)

	if err := client.Mail(from); err != nil {
		return fmt.Errorf("relay MAIL FROM <%s>: %w", from, err)
	}
	for _, rcpt := range rcpts {
		if err := client.Rcpt(rcpt); err != nil {
			return fmt.Errorf("relay RCPT TO <%s>: %w", rcpt, err)
		}
	}
	e.tracePhase(traceID, "relay_smtp_data", fmt.Sprintf("%d bytes", len(data)))
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
	e.logV("[DELIVERY]   relay DATA sent (%d bytes) → ok", len(data))
	client.Quit()
	return nil
}

func (e *Engine) sendToMX(from, domain, mxHost, port string, rcpts []string, data []byte,
	onRcptBounce func(rcpt, reason string), traceID string, connectTimeout time.Duration) error {
	addr := net.JoinHostPort(mxHost, port)
	e.tracePhase(traceID, "outbound_ip_pick", domain)
	e.logV("[DELIVERY]   connecting to %s …", addr)

	var releaseIPTok func()
	defer func() {
		if releaseIPTok != nil {
			releaseIPTok()
		}
	}()

	var conn net.Conn
	var err error

	var outIP, outHostname string
	var ipErr error
	if e.usePerOutboundPipeline() {
		outIP, outHostname, releaseIPTok, ipErr = e.claimOutboundIPForSMTP(domain, traceID)
		if ipErr != nil {
			e.tracePhase(traceID, "ip_pool_all_busy", ipErr.Error())
			return ipErr
		}
	} else {
		outIP, outHostname, ipErr = e.nextOutboundIP(domain)
		if ipErr != nil {
			e.tracePhase(traceID, "ip_pool_all_busy", ipErr.Error())
			return ipErr
		}
	}
	usedPoolIP := false
	if outIP != "" {
		dialer := &net.Dialer{
			Timeout:   connectTimeout,
			LocalAddr: &net.TCPAddr{IP: net.ParseIP(outIP)},
		}
		e.tracePhase(traceID, "tcp_dial_bind", fmt.Sprintf("src=%s → %s", outIP, addr))
		e.logV("[IPPOOL]   selected outbound IP %s → %s", outIP, addr)
		conn, err = dialer.Dial(e.dialNetwork, addr)
		if err != nil {
			// Binding to this pool IP failed (not assigned to interface or OS error).
			// Undo the reservation so the counter stays accurate, then fall back.
			e.undoIPCount(outIP, domain)
			if releaseIPTok != nil {
				releaseIPTok()
				releaseIPTok = nil
			}
			e.logV("[IPPOOL] ✗ bind to %s FAILED: %v — falling back to system default IP", outIP, err)
			e.tracePhase(traceID, "tcp_dial_fallback", addr)
			conn, err = net.DialTimeout(e.dialNetwork, addr, connectTimeout)
		} else {
			usedPoolIP = true
		}
	} else {
		// Pool is disabled/empty — use system default IP.
		e.tracePhase(traceID, "tcp_dial_system", addr)
		conn, err = net.DialTimeout(e.dialNetwork, addr, connectTimeout)
	}
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	e.tracePhase(traceID, "tcp_connected", addr)
	e.logV("[DELIVERY]   TCP connected to %s", addr)

	// HELO must match rDNS/PTR for the outbound IP. If we used a pool IP with a hostname, use it.
	heloName := e.cfg.HeloName
	if heloName == "" {
		heloName = "localhost"
	}
	if usedPoolIP && outHostname != "" {
		heloName = outHostname
		e.logV("[IPPOOL]   HELO %s (matches rDNS for %s)", heloName, outIP)
	}

	client, err := smtp.NewClient(conn, mxHost)
	if err != nil {
		conn.Close()
		return fmt.Errorf("new client: %w", err)
	}
	defer client.Close()

	e.tracePhase(traceID, "smtp_ehlo", heloName)
	if err := client.Hello(heloName); err != nil {
		return fmt.Errorf("EHLO: %w", err)
	}
	e.logV("[DELIVERY]   EHLO %s → ok", heloName)

	if ok, _ := client.Extension("STARTTLS"); ok {
		e.logV("[DELIVERY]   STARTTLS supported, upgrading …")
		tlsCfg := &tls.Config{
			ServerName:         mxHost,
			InsecureSkipVerify: false,
		}
		if err := client.StartTLS(tlsCfg); err != nil {
			e.logV("[DELIVERY] ⚠ STARTTLS failed (continuing plain): %v", err)
		} else {
			e.logV("[DELIVERY]   STARTTLS ok (TLS active)")
		}
	} else {
		e.logV("[DELIVERY]   STARTTLS not supported, sending plain")
	}

	e.tracePhase(traceID, "smtp_mail_from", from)
	if err := client.Mail(from); err != nil {
		return fmt.Errorf("MAIL FROM <%s>: %w", from, err)
	}
	e.logV("[DELIVERY]   MAIL FROM <%s> → ok", from)

	// ── RCPT TO — per-recipient handling ──────────────────────────────────
	// A 5xx on RCPT TO is a permanent per-recipient rejection (mailbox not
	// found, user suspended, etc.).  We call the bounce callback for that
	// recipient and continue trying the remaining ones so a single bad
	// address never blocks a valid one in the same batch.
	// If ALL recipients are rejected we abort immediately; DATA is never sent.
	e.tracePhase(traceID, "smtp_rcpt_to", fmt.Sprintf("%d recipients", len(rcpts)))
	var accepted []string
	var lastRcptBounceErr error
	for _, rcpt := range rcpts {
		if err := client.Rcpt(rcpt); err != nil {
			if isPermanentSMTPError(err) {
				reason := fmt.Sprintf("RCPT TO <%s>: %v", rcpt, err)
				e.logV("[DELIVERY] ✗ RCPT TO <%s> → hard bounce (5xx) — aborting for this recipient: %v",
					rcpt, err)
				if onRcptBounce != nil {
					onRcptBounce(rcpt, reason)
				}
				lastRcptBounceErr = fmt.Errorf("%s: %w", reason, err)
				continue // skip to next recipient — do NOT abort the whole session yet
			}
			// Temporary RCPT error — abort and retry later.
			e.logV("[DELIVERY] ✗ RCPT TO <%s> → temp error (will retry): %v", rcpt, err)
			client.Quit()
			return fmt.Errorf("RCPT TO <%s>: %w", rcpt, err)
		}
		e.logV("[DELIVERY]   RCPT TO <%s> → ok", rcpt)
		accepted = append(accepted, rcpt)
	}

	if len(accepted) == 0 {
		// Every recipient was permanently rejected — abort without sending DATA.
		e.logV("[DELIVERY] ✗ all %d recipient(s) hard-bounced during RCPT — session aborted, DATA not sent",
			len(rcpts))
		client.Quit()
		// Return the last bounce error so isPermanentSMTPError fires in the caller.
		return lastRcptBounceErr
	}
	if len(accepted) < len(rcpts) {
		e.logV("[DELIVERY]   %d/%d recipient(s) accepted for DATA (rest hard-bounced)",
			len(accepted), len(rcpts))
	}
	// ── end RCPT TO ────────────────────────────────────────────────────────

	e.tracePhase(traceID, "smtp_data_body", fmt.Sprintf("%d bytes", len(data)))
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
	e.logV("[DELIVERY]   DATA sent (%d bytes) to %d recipient(s) → ok", n, len(accepted))

	if err := client.Quit(); err != nil {
		e.logV("[DELIVERY] ⚠ QUIT error (message was accepted): %v", err)
	}
	return nil
}

// ---- Header injection ----

// injectMissingHeaders ensures the message has the required RFC 5322 headers
// (From, Message-ID, Date) that Gmail and other providers reject without.
func injectMissingHeaders(data []byte, domain, fromAddr string) []byte {
	header, body, found := bytes.Cut(data, []byte("\r\n\r\n"))
	if !found {
		// Try Unix line endings
		header, body, found = bytes.Cut(data, []byte("\n\n"))
		if !found {
			return data
		}
	}

	headerStr := string(header)
	// From header is required by RFC 5322; Gmail rejects messages without it
	if getFromHeaderValue(headerStr) == "" {
		addr := strings.TrimSpace(fromAddr)
		if addr == "" {
			addr = "noreply@" + domain
		}
		if addr != "" && !strings.Contains(addr, "@") {
			addr = "noreply@" + domain
		}
		if addr != "" {
			if !strings.Contains(addr, "<") {
				addr = "<" + addr + ">"
			}
			headerStr = fixOrInjectFromHeader(headerStr, "From: "+addr)
		}
	}

	var inject strings.Builder
	if !containsHeader(headerStr, "Message-ID") {
		b := make([]byte, 12)
		rand.Read(b)
		msgID := fmt.Sprintf("Message-ID: <%d.%s@%s>\r\n",
			time.Now().UnixNano(), hex.EncodeToString(b), domain)
		inject.WriteString(msgID)
	}

	if !containsHeader(headerStr, "Date") {
		inject.WriteString("Date: " + time.Now().Format("Mon, 02 Jan 2006 15:04:05 -0700") + "\r\n")
	}

	if inject.Len() == 0 {
		return data
	}

	sep := "\r\n\r\n"
	if !bytes.Contains(data, []byte("\r\n\r\n")) {
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

// fixOrInjectFromHeader replaces an empty/missing From header with a valid one.
func fixOrInjectFromHeader(headerStr, fromLine string) string {
	needsFrom := getFromHeaderValue(headerStr) == ""
	if !needsFrom {
		return headerStr
	}
	lines := strings.Split(strings.ReplaceAll(headerStr, "\r\n", "\n"), "\n")
	var out []string
	added := false
	skipNext := false
	for _, line := range lines {
		if skipNext {
			if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
				continue
			}
			skipNext = false
		}
		trimmed := strings.TrimSpace(line)
		if len(trimmed) >= 5 && strings.EqualFold(trimmed[:5], "From:") {
			// Replace empty From with valid one
			out = append(out, fromLine)
			added = true
			skipNext = true
			continue
		}
		out = append(out, line)
	}
	if !added {
		out = append([]string{fromLine}, out...)
	}
	return strings.ReplaceAll(strings.Join(out, "\n"), "\n", "\r\n")
}

// getFromHeaderValue returns the value of the From header, or empty if missing/invalid.
func getFromHeaderValue(headerStr string) string {
	lower := strings.ToLower(headerStr)
	idx := strings.Index(lower, "from:")
	if idx < 0 {
		return ""
	}
	// Get rest of line after "from:"
	rest := headerStr[idx+5:]
	if nl := strings.IndexAny(rest, "\r\n"); nl >= 0 {
		rest = rest[:nl]
	}
	val := strings.TrimSpace(rest)
	// Must contain @ to be a valid address
	if val == "" || !strings.Contains(val, "@") {
		return ""
	}
	return val
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

// stripDKIMSignatureHeaders removes all DKIM-Signature fields (including folded continuation lines)
// so a relay server can add a fresh signature without stacking or invalidating body hash from upstream.
func stripDKIMSignatureHeaders(data []byte) []byte {
	idx := bytes.Index(data, []byte("\r\n\r\n"))
	var head, body []byte
	if idx >= 0 {
		head = data[:idx]
		body = data[idx+4:]
	} else {
		idx = bytes.Index(data, []byte("\n\n"))
		if idx < 0 {
			return data
		}
		head = data[:idx]
		body = data[idx+2:]
	}
	shead := strings.ReplaceAll(string(head), "\r\n", "\n")
	lines := strings.Split(shead, "\n")
	var kept []string
	inSkip := false
	for _, line := range lines {
		if line == "" {
			continue
		}
		isCont := line[0] == ' ' || line[0] == '\t'
		if isCont {
			if inSkip {
				continue
			}
			kept = append(kept, line)
			continue
		}
		inSkip = strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "dkim-signature:")
		if inSkip {
			continue
		}
		kept = append(kept, line)
	}
	newHead := strings.Join(kept, "\r\n")
	return append(append([]byte(newHead), []byte("\r\n\r\n")...), body...)
}

func (e *Engine) resolveDKIMSigner(data []byte) *dkim.SignOptions {
	forced := strings.TrimSpace(e.cfg.OutboundDKIMDomain)
	if forced != "" {
		if e.DKIMKeyLoader != nil {
			if privPEM, sel, ok := e.DKIMKeyLoader(forced); ok {
				dbSigner, err := parseDKIMSignerFromPEM(forced, sel, privPEM)
				if err != nil {
					log.Printf("[DELIVERY] ⚠ outbound_dkim_domain %q: invalid DB key PEM: %v", forced, err)
				} else {
					e.logV("[DELIVERY]   DKIM: outbound_dkim_domain %q (Admin Domains key)", forced)
					return dbSigner
				}
			}
		}
		if e.dkimSigner != nil && strings.EqualFold(strings.TrimSpace(e.cfg.DKIM.Domain), forced) {
			e.logV("[DELIVERY]   DKIM: outbound_dkim_domain %q (config dkim private key)", forced)
			return e.dkimSigner
		}
		log.Printf("[DELIVERY] ⚠ outbound_dkim_domain=%q: add DKIM key in Admin→Domains for this domain, or set delivery.dkim.domain to match and enable dkim", forced)
	}

	signer := e.dkimSigner
	if e.DKIMKeyLoader != nil {
		fromDomain := extractFromDomain(data)
		if fromDomain != "" {
			if privPEM, sel, ok := e.DKIMKeyLoader(fromDomain); ok {
				if dbSigner, err := parseDKIMSignerFromPEM(fromDomain, sel, privPEM); err == nil {
					signer = dbSigner
					e.logV("[DELIVERY]   using DB DKIM key for From domain %q selector=%q", fromDomain, sel)
				}
			}
		}
	}
	return signer
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
