package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/pflag"

	"github.com/yarlson/zero/internal/acme"
	"github.com/yarlson/zero/internal/cert"
	"github.com/yarlson/zero/internal/hook"
	"github.com/yarlson/zero/internal/server"
	"github.com/yarlson/zero/internal/task"
	"github.com/yarlson/zero/internal/zero"
)

const (
	defaultCertDir = "./certs"
	defaultPort    = 80
	defaultTime    = "02:00"
)

type Config struct {
	Domain        string
	Email         string
	CertDir       string
	Time          string
	Port          int
	Hook          string
	HookContainer string
}

func parseFlags() (*Config, error) {
	cfg := &Config{}

	pflag.StringVarP(&cfg.Domain, "domain", "d", "", "Domain name for the certificate")
	pflag.StringVarP(&cfg.Email, "email", "e", "", "Email address for account registration")
	pflag.StringVarP(&cfg.CertDir, "cert-dir", "c", defaultCertDir, "Directory to store certificates")
	pflag.StringVarP(&cfg.Time, "time", "t", defaultTime, "Time for daily renewal in HH:mm format")
	pflag.IntVarP(&cfg.Port, "port", "p", defaultPort, "HTTP port for ACME challenges")
	pflag.StringVar(&cfg.Hook, "hook", "", "Command to execute after certificate renewal")
	pflag.StringVar(&cfg.HookContainer, "hook-container", "", "Container name or network alias to execute hook in")

	pflag.Usage = func() {
		_, _ = fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		_, _ = fmt.Fprintf(os.Stderr, "  %s -d example.com -e user@example.com [-c /path/to/certs] [--time HH:mm] [-p port]\n\n", os.Args[0])
		_, _ = fmt.Fprintf(os.Stderr, "Options:\n")
		pflag.PrintDefaults()
	}

	pflag.Parse()

	if cfg.Domain == "" || cfg.Email == "" {
		return nil, errors.New("domain and email are required")
	}

	if _, err := task.ParseTime(cfg.Time); err != nil {
		return nil, fmt.Errorf("invalid time format: %w", err)
	}

	return cfg, nil
}

func main() {
	cfg, err := parseFlags()
	if err != nil {
		log.Fatalf("Error parsing flags: %v", err)
	}

	if err := os.MkdirAll(cfg.CertDir, 0700); err != nil {
		log.Fatalf("Create cert directory: %v", err)
	}

	// Create hook if specified
	var hookInstance *hook.Hook
	if cfg.Hook != "" {
		hookInstance = hook.New(cfg.Hook, cfg.HookContainer)
	}

	// Setup services
	zeroSSL := acme.NewZeroSSL()
	store := cert.NewStore()
	zeroManager := zero.NewManager(zeroSSL, store, hookInstance)

	// Start HTTP server
	srv := server.New(store, cfg.Port)
	go func() {
		if err := srv.Start(); err != nil {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	// Start certificate checker
	checkCert := func(ctx context.Context) error {
		return zeroManager.CheckCertificate(ctx, cfg.Domain, cfg.Email, cfg.CertDir)
	}

	scheduler := task.NewScheduler(checkCert, cfg.Time)
	go scheduler.Start()

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down...")
	scheduler.Stop()
	time.Sleep(time.Second)
}
