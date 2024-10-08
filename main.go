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
}

func parseFlags() (*Config, error) {
	cfg := &Config{}

	pflag.StringVarP(&cfg.Domain, "domain", "d", "", "Domain name for the certificate")
	pflag.StringVarP(&cfg.Email, "email", "e", "", "Email address for account registration")
	pflag.StringVarP(&cfg.CertDir, "cert-dir", "c", defaultCertDir, "Directory to store certificates")
	pflag.BoolVarP(&cfg.Issue, "issue", "i", false, "Issue a new certificate")
	pflag.BoolVarP(&cfg.Renew, "renew", "r", false, "Renew the existing certificate")

	pflag.Usage = func() {
		_, _ = fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		_, _ = fmt.Fprintf(os.Stderr, "  %s -d example.com -e user@example.com [-c /path/to/certs] [-i] [-r]\n\n", os.Args[0])
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

	return cfg, nil
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

	// Set up signal handling for graceful shutdown
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

func main() {
	cfg, err := parseFlags()
	if err != nil {
		log.Fatalf("Error parsing flags: %v", err)
	}

	if err := run(cfg); err != nil {
		log.Fatalf("Error: %v", err)
	}
}
