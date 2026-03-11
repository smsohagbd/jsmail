package main

import (
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"strconv"
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

	// Initialize SQLite database and JWT auth.
	if err := appdb.Init(cfg.Web.DBPath, cfg.Admin.Username, cfg.Admin.Password); err != nil {
		log.Fatalf("main: DB init failed: %v", err)
	}
	webauth.Init(cfg.Web.SecretKey)

	// Build the queue first — all other components reference it.
	q := queue.New(cfg.Queue)

	// Start the outbound delivery engine.
	eng := delivery.New(cfg.Delivery, q)

	// Wire delivery events to DB log updates.
	eng.OnEvent = func(evt delivery.DeliveryEvent) {
		switch evt.Status {
		case "delivered":
			appdb.LogDelivered(evt.MessageID, evt.To, evt.MXHost)
		case "failed":
			appdb.LogFailed(evt.MessageID, evt.To, evt.Error)
		case "deferred":
			appdb.LogDeferred(evt.MessageID, evt.To, evt.Error)
		case "hard_bounce":
			appdb.LogHardBounce(evt.MessageID, evt.To, evt.Error)
		case "suppressed":
			appdb.LogSuppressed(evt.MessageID, evt.To, evt.Error)
		}
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
			PerSec:   lim.PerSec,
			PerMin:   lim.PerMin,
			PerHour:  lim.PerHour,
			PerDay:   lim.PerDay,
			PerMonth: lim.PerMonth,
		}
	}

	// Custom SMTP relay: returns delivery mode + active relay list for a user.
	eng.UserSMTPProvider = func(username string) (mode string, relays []delivery.SMTPRelay) {
		mode, _ = appdb.GetUserSMTPMode(username)
		if mode == "system_only" || mode == "" {
			return "system_only", nil
		}
		dbRelays := appdb.GetActiveUserSMTPs(username)
		out := make([]delivery.SMTPRelay, 0, len(dbRelays))
		for _, r := range dbRelays {
			out = append(out, delivery.SMTPRelay{
				ID:       r.ID,
				Label:    r.Label,
				Host:     r.Host,
				Port:     r.Port,
				Username: r.Username,
				Password: r.Password,
				UseTLS:   r.UseTLS,
			})
		}
		return mode, out
	}

	// IP pool: round-robin with per-IP rate limits from DB table.
	eng.IPPoolProvider = func() []delivery.IPEntry {
		if appdb.GetSetting("ip_pool_enabled", "false") != "true" {
			return nil
		}
		pool := appdb.GetActiveIPPool()
		entries := make([]delivery.IPEntry, 0, len(pool))
		for _, p := range pool {
			entries = append(entries, delivery.IPEntry{
				IP:           p.IP,
				PerMin:       p.PerMin,
				PerHour:      p.PerHour,
				PerDay:       p.PerDay,
				WarmupPerDay: p.WarmupDayLimit(),
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
	cfgSnapshot := map[string]string{
		"smtp_listen":     cfg.SMTP.ListenAddr,
		"smtp_domain":     cfg.SMTP.Domain,
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
		"db_path":         cfg.Web.DBPath,
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
