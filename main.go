package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/pflag"

	"github.com/yarlson/zero/certificates"
	"github.com/yarlson/zero/zerossl"
)

const (
	defaultCertDir = "./certs"
)

type Config struct {
	Domain  string
	Email   string
	CertDir string
	Issue   bool
	Renew   bool
	Cron    bool
	Time    string
}

func parseFlags() (*Config, error) {
	cfg := &Config{}

	pflag.StringVarP(&cfg.Domain, "domain", "d", "", "Domain name for the certificate")
	pflag.StringVarP(&cfg.Email, "email", "e", "", "Email address for account registration")
	pflag.StringVarP(&cfg.CertDir, "cert-dir", "c", defaultCertDir, "Directory to store certificates")
	pflag.BoolVarP(&cfg.Issue, "issue", "i", false, "Issue a new certificate")
	pflag.BoolVarP(&cfg.Renew, "renew", "r", false, "Renew the existing certificate")
	pflag.BoolVar(&cfg.Cron, "cron", false, "Run in cron mode for daily renewals")
	pflag.StringVar(&cfg.Time, "time", "02:00", "Time for daily renewal in HH:mm format (24-hour or 12-hour with AM/PM)")

	pflag.Usage = func() {
		_, _ = fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		_, _ = fmt.Fprintf(os.Stderr, "  %s -d example.com -e user@example.com [-c /path/to/certs] [-i] [-r] [--cron] [--time HH:mm]\n\n", os.Args[0])
		_, _ = fmt.Fprintf(os.Stderr, "Options:\n")
		pflag.PrintDefaults()
	}

	pflag.Parse()

	if cfg.Domain == "" || cfg.Email == "" {
		return nil, errors.New("domain and email are required")
	}

	if cfg.Issue && cfg.Renew {
		return nil, errors.New("cannot specify both --issue and --renew")
	}

	if cfg.Cron {
		if _, err := parseTime(cfg.Time); err != nil {
			return nil, fmt.Errorf("invalid time format: %w", err)
		}
	}

	return cfg, nil
}

func parseTime(timeStr string) (time.Time, error) {
	formats := []string{
		"15:04",
		"3:04PM",
		"3:04 PM",
	}

	for _, format := range formats {
		t, err := time.Parse(format, timeStr)
		if err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("unable to parse time: %s", timeStr)
}

func run(cfg *Config) error {
	if err := os.MkdirAll(cfg.CertDir, 0700); err != nil {
		return fmt.Errorf("create cert directory: %w", err)
	}

	certFile := filepath.Join(cfg.CertDir, cfg.Domain+".crt")
	keyFile := filepath.Join(cfg.CertDir, cfg.Domain+".key")

	action := "auto"
	if cfg.Issue {
		action = "issue"
	} else if cfg.Renew {
		action = "renew"
	}

	zeroSSLService := zerossl.New()
	certService := certificates.New(zeroSSLService)

	cert, err := certService.LoadCertificate(certFile)
	if err != nil && action != "issue" {
		log.Printf("Load existing certificate: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Received interrupt signal. Shutting down...")
		cancel()
	}()

	if certService.ShouldObtainCertificate(action, cert) {
		log.Printf("Obtaining certificate for %s", cfg.Domain)
		if err := certService.ObtainOrRenewCertificate(ctx, cfg.Domain, cfg.Email, certFile, keyFile); err != nil {
			if errors.Is(err, context.Canceled) {
				return errors.New("operation canceled")
			}
			return fmt.Errorf("failed to obtain/renew certificate: %w", err)
		}
	} else if cert == nil {
		log.Println("No existing certificate found.")
	} else {
		log.Printf("Certificate is valid until %s. No action needed.", cert.NotAfter.Format(time.RFC3339))
	}

	return nil
}

func runCron(cfg *Config) error {
	renewalTime, err := parseTime(cfg.Time)
	if err != nil {
		return fmt.Errorf("parse renewal time: %w", err)
	}

	log.Printf("Starting cron mode. Daily renewal scheduled at %s", renewalTime.Format("15:04"))

	ticker := time.NewTicker(getNextTickDuration(renewalTime))
	defer ticker.Stop()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case <-ticker.C:
			log.Println("Running scheduled renewal")
			if err := run(cfg); err != nil {
				log.Printf("Error during scheduled renewal: %v", err)
			}
			ticker.Reset(24 * time.Hour)
		case <-sigChan:
			log.Println("Received interrupt signal. Shutting down...")
			return nil
		}
	}
}

func getNextTickDuration(t time.Time) time.Duration {
	now := time.Now()
	next := time.Date(now.Year(), now.Month(), now.Day(), t.Hour(), t.Minute(), 0, 0, now.Location())
	if next.Before(now) {
		next = next.Add(24 * time.Hour)
	}

	return next.Sub(now)
}

func main() {
	cfg, err := parseFlags()
	if err != nil {
		log.Fatalf("Error parsing flags: %v", err)
	}

	if cfg.Cron {
		if err := runCron(cfg); err != nil {
			log.Fatalf("Error in cron mode: %v", err)
		}
		return
	}

	if err := run(cfg); err != nil {
		log.Fatalf("Error: %v", err)
	}
}
