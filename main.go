package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"smtp-server/internal/api"
	"smtp-server/internal/config"
	appdb "smtp-server/internal/db"
	"smtp-server/internal/delivery"
	"smtp-server/internal/queue"
	"smtp-server/internal/server"
	"smtp-server/internal/verifier"
	"smtp-server/internal/web"
	webauth "smtp-server/internal/web/auth"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			log.Printf("main: config file %q not found, using defaults", *configPath)
			cfg = config.Default()
		} else {
			log.Fatalf("main: failed to load config: %v", err)
		}
	}

	// Redirect log output to a file when configured (avoids slow console I/O
	// on Windows which can block delivery workers contending on the log mutex).
	if logFile := cfg.Logging.File; logFile != "" {
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Fatalf("main: cannot open log file %q: %v", logFile, err)
		}
		defer f.Close()
		log.SetOutput(f)
		log.Printf("main: logging to file %q", logFile)
	}

	// Initialize database (SQLite or MySQL) and JWT auth.
	driver, dsn := dbDSN(cfg)
	if err := appdb.Init(driver, dsn, cfg.Admin.Username, cfg.Admin.Password); err != nil {
		log.Fatalf("main: DB init failed: %v", err)
	}
	webauth.Init(cfg.Web.SecretKey)

	// Build the queue first — all other components reference it.
	q := queue.New(cfg.Queue)

	// Start the outbound delivery engine.
	eng := delivery.New(cfg.Delivery, q)

	// Wire delivery events to DB log updates.
	eng.OnEvent = func(evt delivery.DeliveryEvent) {
		eng.RecordDeliveryTelemetry(evt.Status)
		switch evt.Status {
		case "delivered":
			appdb.LogDelivered(evt.Username, evt.MessageID, evt.To, evt.MXHost)
			appdb.UpdateCampaignSendByMessageID(evt.MessageID, "sent")
		case "failed":
			appdb.LogFailed(evt.Username, evt.MessageID, evt.To, evt.Error)
			appdb.UpdateCampaignSendByMessageID(evt.MessageID, "failed")
		case "deferred":
			appdb.LogDeferred(evt.Username, evt.MessageID, evt.To, evt.Error)
		case "hard_bounce":
			appdb.LogHardBounce(evt.Username, evt.MessageID, evt.To, evt.Error)
			appdb.UpdateCampaignSendByMessageID(evt.MessageID, "failed")
			// Auto-suppress: hard bounces are permanent failures.
			// Add to suppression list so the address is never retried.
			appdb.AddSuppression(evt.Username, evt.To, "hard_bounce: "+evt.Error, "auto")
		case "suppressed":
			appdb.LogSuppressed(evt.Username, evt.MessageID, evt.To, evt.Error)
			appdb.UpdateCampaignSendByMessageID(evt.MessageID, "failed")
			// Auto-suppress: if verify-before-send confirmed mailbox does not exist,
			// add to suppression list so future sends skip the probe entirely.
			if strings.Contains(evt.Error, "mailbox does not exist") {
				appdb.AddSuppression(evt.Username, evt.To, "verify: "+evt.Error, "auto")
			}
		}
	}

	// Admin domain skip list: silently drop mail to blocked domains before any SMTP handshake.
	eng.SkipDomainChecker = appdb.IsDomainSkipped

	// Email verifier: used by relays that have VerifyBeforeSend enabled.
	// The verifier (v) is created later in web server setup; set it here via a closure
	// so the reference is captured once the verifier is initialised.
	var verifierRef *verifier.Verifier
	eng.EmailVerifier = func(email string) (bool, string) {
		if verifierRef == nil {
			return true, ""
		}
		r := verifierRef.Verify(email)
		return r.Valid, r.Reason
	}

	// Suppression list: skip opted-out recipients at delivery time.
	eng.SuppressionChecker = appdb.IsSuppressed

	// Unsubscribe header injection: use the SMTP domain as the public base URL.
	// Admins can override this via Settings → unsub_base_url.
	eng.UnsubBaseURL = appdb.GetSetting("unsub_base_url", "https://"+cfg.SMTP.Domain)
	eng.UnsubTokenFn = appdb.GenerateUnsubToken

	// Per-domain DKIM: load key from DB based on the From: domain.
	eng.DKIMKeyLoader = func(domain string) (privKeyPEM, selector string, ok bool) {
		if d, found := appdb.GetDomainByName(domain); found && d.DKIMPrivKey != "" {
			return d.DKIMPrivKey, d.DKIMSelector, true
		}
		return "", "", false
	}

	// Per-user throttling: look up the most specific throttle rule from the DB.
	eng.ThrottleProvider = func(username, domain string) delivery.ThrottleLimit {
		lim := appdb.GetEffectiveThrottle(username, domain)
		return delivery.ThrottleLimit{
			PerSec:      lim.PerSec,
			PerMin:      lim.PerMin,
			PerHour:     lim.PerHour,
			PerDay:      lim.PerDay,
			PerMonth:    lim.PerMonth,
			IntervalSec: lim.IntervalSec,
		}
	}

	// Custom SMTP relay: returns delivery mode + active relay list for a user.
	eng.UserSMTPProvider = func(username string) (mode string, relays []delivery.SMTPRelay) {
		var rotation bool
		mode, rotation = appdb.GetUserSMTPMode(username)
		if mode == "system_only" || mode == "" {
			return "system_only", nil
		}

		dbRelays := appdb.GetActiveUserSMTPs(username)

		// Build relay list (GetActiveUserSMTPs sorts is_default DESC, so index 0 = default relay).
		out := make([]delivery.SMTPRelay, 0, len(dbRelays))
		for _, r := range dbRelays {
			tlsMode := r.TLSMode
			if tlsMode == "" {
				if r.UseTLS {
					tlsMode = "starttls"
				} else {
					tlsMode = "auto"
				}
			}
			out = append(out, delivery.SMTPRelay{
				ID:               r.ID,
				Label:            r.Label,
				Host:             r.Host,
				Port:             r.Port,
				Username:         r.Username,
				Password:         r.Password,
				TLSMode:          tlsMode,
				FromAddress:      r.FromAddress,
				LimitPerMin:      r.LimitPerMin,
				LimitPerHour:     r.LimitPerHour,
				LimitPerDay:      r.LimitPerDay,
				VerifyBeforeSend: r.VerifyBeforeSend,
			})
		}

		// Rotation OFF → system direct delivery (no relay).
		if !rotation {
			return "system_only", nil
		}

		// Rotation ON → use the configured mode with all relays.
		// system_and_custom: round-robin includes system MX slot + all custom relays.
		// custom_only: round-robin through custom relays only.
		return mode, out
	}

	// IP pool: round-robin with per-IP and per-domain rate limits from DB.
	eng.IPPoolMasterProvider = func(domain string) (perMin, perHour, perDay, intervalSec int, found bool) {
		r := appdb.GetIPPoolMasterDomainRule(domain)
		if r == nil {
			return 0, 0, 0, 0, false
		}
		return r.PerMin, r.PerHour, r.PerDay, r.IntervalSec, true
	}
	eng.PriorityUserProvider = func(username string) bool {
		return appdb.IsUserPriority(username)
	}

	eng.UserIPFilterProvider = func(username string) map[string]bool {
		// IPs explicitly assigned to this user.
		userIPs := appdb.GetUserAssignedIPSet(username)
		if len(userIPs) > 0 {
			// User has specific IPs → use only those, regardless of other users.
			return userIPs
		}

		// User has no personal assignment. Build a pool of IPs that are NOT
		// assigned to any other user, so assigned IPs remain exclusive.
		allAssigned := appdb.GetAllAssignedIPs()
		if len(allAssigned) == 0 {
			// No assignments exist anywhere → full shared pool.
			return nil
		}

		// Collect every active pool IP, then remove the globally assigned ones.
		allEntries := eng.IPPoolProvider()
		available := make(map[string]bool, len(allEntries))
		for _, e := range allEntries {
			if !allAssigned[e.IP] {
				available[e.IP] = true
			}
		}
		// Return the filtered set (may be empty if all IPs are assigned to
		// specific users; the engine will then fall back to system default).
		return available
	}

	eng.IPPoolProvider = func() []delivery.IPEntry {
		if appdb.GetSetting("ip_pool_enabled", "false") != "true" {
			return nil
		}
		pool := appdb.GetActiveIPPool()
		entries := make([]delivery.IPEntry, 0, len(pool))
		for _, p := range pool {
			rules := appdb.GetIPPoolDomainRules(p.ID)
			domainRules := make([]delivery.IPDomainRule, 0, len(rules))
			for _, r := range rules {
				domainRules = append(domainRules, delivery.IPDomainRule{
					Domain:      r.Domain,
					PerMin:      r.PerMin,
					PerHour:     r.PerHour,
					PerDay:      r.PerDay,
					IntervalSec: r.IntervalSec,
				})
			}
			entries = append(entries, delivery.IPEntry{
				IP:           p.IP,
				Hostname:     p.Hostname,
				PerMin:       p.PerMin,
				PerHour:      p.PerHour,
				PerDay:       p.PerDay,
				WarmupPerDay: p.WarmupDayLimit(),
				IntervalSec:  p.IntervalSec,
				DomainRules:  domainRules,
			})
		}
		return entries
	}

	eng.Start()

	// Start the HTTP injection API.
	go api.New(cfg.API, q, cfg.Delivery.HeloName).Start()

	// Start the SMTP submission server.
	go func() {
		if err := server.Start(cfg.SMTP, q); err != nil {
			log.Fatalf("main: SMTP server stopped: %v", err)
		}
	}()

	// Start the web UI server.
	v := verifier.New(verifier.Config{HeloName: cfg.Delivery.HeloName})
	verifierRef = v // wire the delivery engine's verify-before-send hook
	dbDisplay := cfg.Database.Path
	if cfg.Database.Driver == "mysql" {
		dbDisplay = fmt.Sprintf("mysql:%s:%d/%s", cfg.Database.Host, cfg.Database.Port, cfg.Database.Database)
	}
	webBaseURL := cfg.Web.BaseURL
	if webBaseURL == "" {
		webBaseURL = "https://" + cfg.SMTP.Domain
	}
	cfgSnapshot := map[string]string{
		"smtp_listen":         cfg.SMTP.ListenAddr,
		"smtp_domain":         cfg.SMTP.Domain,
		"web_base_url":        webBaseURL,
		"unlayer_project_id":  strconv.Itoa(cfg.Web.UnlayerProjectID),
		"tls_enabled":     boolStr(cfg.SMTP.TLS.Enabled),
		"tls_cert_file":   cfg.SMTP.TLS.CertFile,
		"tls_key_file":    cfg.SMTP.TLS.KeyFile,
		"tls_mode":        cfg.SMTP.TLS.Mode,
		"dkim_enabled":    boolStr(cfg.Delivery.DKIM.Enabled),
		"max_retries":     strconv.Itoa(cfg.Delivery.MaxRetries),
		"connect_timeout": cfg.Delivery.ConnectTimeout,
		"workers":         strconv.Itoa(cfg.Delivery.Workers),
		"api_listen":      cfg.API.ListenAddr,
		"api_token":       cfg.API.AuthToken,
		"web_listen":      cfg.Web.ListenAddr,
		"db_path":         dbDisplay,
	}
	go web.NewServer(cfg.Web.ListenAddr, appdb.DB, q, eng, v, cfgSnapshot, *configPath).Start()

	log.Printf("=== smtp-server started ===")
	log.Printf("  SMTP  : %s  (domain: %s)", cfg.SMTP.ListenAddr, cfg.SMTP.Domain)
	log.Printf("  API   : %s", cfg.API.ListenAddr)
	log.Printf("  Web   : %s  (admin: %s)", cfg.Web.ListenAddr, cfg.Admin.Username)
	log.Printf("  Queue : %s", cfg.Queue.Dir)
	log.Printf("  TLS   : %v", cfg.SMTP.TLS.Enabled)
	log.Printf("  DKIM  : %v", cfg.Delivery.DKIM.Enabled)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("main: shutting down")
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// dbDSN returns (driver, dsnOrPath) for appdb.Init.
func dbDSN(cfg *config.Config) (string, string) {
	if cfg.Database.Driver == "mysql" {
		dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=%s&parseTime=True&loc=Local",
			cfg.Database.User, cfg.Database.Password,
			cfg.Database.Host, cfg.Database.Port,
			cfg.Database.Database, cfg.Database.Charset)
		return "mysql", dsn
	}
	return "sqlite", cfg.Database.Path
}
