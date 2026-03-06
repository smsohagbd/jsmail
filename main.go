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
		}
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
		"dkim_enabled":    boolStr(cfg.Delivery.DKIM.Enabled),
		"max_retries":     strconv.Itoa(cfg.Delivery.MaxRetries),
		"connect_timeout": cfg.Delivery.ConnectTimeout,
		"workers":         strconv.Itoa(cfg.Delivery.Workers),
		"api_listen":      cfg.API.ListenAddr,
		"api_token":       cfg.API.AuthToken,
		"web_listen":      cfg.Web.ListenAddr,
		"db_path":         cfg.Web.DBPath,
	}
	go web.NewServer(cfg.Web.ListenAddr, appdb.DB, q, v, cfgSnapshot).Start()

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
