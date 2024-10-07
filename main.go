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

	"github.com/yarlson/zero/pkg"
)

func main() {
	var (
		domain  string
		email   string
		certDir string
		issue   bool
		renew   bool
	)

	pflag.StringVarP(&domain, "domain", "d", "", "Domain name for the certificate")
	pflag.StringVarP(&email, "email", "e", "", "Email address for account registration")
	pflag.StringVarP(&certDir, "cert-dir", "c", "./certs", "Directory to store certificates")
	pflag.BoolVarP(&issue, "issue", "i", false, "Issue a new certificate")
	pflag.BoolVarP(&renew, "renew", "r", false, "Renew the existing certificate")

	pflag.Usage = func() {
		_, _ = fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		_, _ = fmt.Fprintf(os.Stderr, "  %s -d example.com -e user@example.com [-c /path/to/certs] [-i] [-r]\n\n", os.Args[0])
		_, _ = fmt.Fprintf(os.Stderr, "Options:\n")
		pflag.PrintDefaults()
	}

	pflag.Parse()

	if domain == "" || email == "" {
		fmt.Println("Error: Domain and email are required.")
		pflag.Usage()
		os.Exit(1)
	}

	if err := os.MkdirAll(certDir, 0700); err != nil {
		log.Fatalf("Create cert directory: %v", err)
	}

	certFile := filepath.Join(certDir, domain+".crt")
	keyFile := filepath.Join(certDir, domain+".key")

	action := pkg.DetermineAction(issue, renew)

	cert, err := pkg.LoadCertificate(certFile)
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

	switch {
	case pkg.ShouldObtainCertificate(action, cert):
		if err := pkg.ObtainOrRenewCertificate(ctx, domain, email, certFile, keyFile); err != nil {
			if errors.Is(err, context.Canceled) {
				log.Println("Operation canceled.")
				return
			}
			log.Fatalf("Failed to obtain/renew certificate: %v", err)
		}
	case cert == nil:
		log.Println("No existing certificate found.")
	default:
		log.Printf("Certificate is valid until %s. No action needed.", cert.NotAfter.Format(time.RFC3339))
	}
}
