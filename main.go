package main

import (
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"smtp-server/internal/api"
	"smtp-server/internal/config"
	"smtp-server/internal/delivery"
	"smtp-server/internal/queue"
	"smtp-server/internal/server"
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

	// Build the queue first — all other components reference it.
	q := queue.New(cfg.Queue)

	// Start the outbound delivery engine.
	eng := delivery.New(cfg.Delivery, q)
	eng.Start()

	// Start the HTTP injection API.
	go api.New(cfg.API, q, cfg.Delivery.HeloName).Start()

	// Start the SMTP submission server.
	go func() {
		if err := server.Start(cfg.SMTP, q); err != nil {
			log.Fatalf("main: SMTP server stopped: %v", err)
		}
	}()

	log.Printf("=== smtp-server started ===")
	log.Printf("  SMTP  : %s  (domain: %s)", cfg.SMTP.ListenAddr, cfg.SMTP.Domain)
	log.Printf("  API   : %s", cfg.API.ListenAddr)
	log.Printf("  Queue : %s", cfg.Queue.Dir)
	log.Printf("  TLS   : %v", cfg.SMTP.TLS.Enabled)
	log.Printf("  DKIM  : %v", cfg.Delivery.DKIM.Enabled)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("main: shutting down")
}
