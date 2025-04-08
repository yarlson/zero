package zero

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"time"

	"github.com/yarlson/zero/internal/acme"
	"github.com/yarlson/zero/internal/cert"
	"github.com/yarlson/zero/internal/hook"
)

const (
	renewBeforeDays = 30
)

type Manager struct {
	zeroSSL *acme.ZeroSSL
	store   *cert.Store
	hook    *hook.Hook
}

func NewManager(zeroSSL *acme.ZeroSSL, store *cert.Store, hook *hook.Hook) *Manager {
	return &Manager{
		zeroSSL: zeroSSL,
		store:   store,
		hook:    hook,
	}
}

func (s *Manager) ObtainOrRenewCertificate(ctx context.Context, domains []string, email, certFile, keyFile string) error {
	certs, privateKey, err := s.zeroSSL.ObtainCertificate(ctx, domains, email, s.store.StoreChallenge)
	if err != nil {
		return fmt.Errorf("obtain certificate: %w", err)
	}

	if err := s.store.SaveCertificate(certFile, certs); err != nil {
		return fmt.Errorf("save certificate: %w", err)
	}
	if err := s.store.SavePrivateKey(keyFile, privateKey); err != nil {
		return fmt.Errorf("save private key: %w", err)
	}

	log.Printf("Certificate saved to: %s", certFile)
	log.Printf("Private key saved to: %s", keyFile)

	if s.hook != nil {
		if err := s.hook.Execute(); err != nil {
			return fmt.Errorf("execute hook: %w", err)
		}
		log.Printf("Hook executed successfully")
	}

	return nil
}

func (s *Manager) CertificateNeedsRenewal(cert *x509.Certificate) bool {
	return time.Now().Add(renewBeforeDays * 24 * time.Hour).After(cert.NotAfter)
}

func (s *Manager) CheckCertificate(ctx context.Context, domains []string, email, certDir string) error {
	var certFile, keyFile string
	if len(domains) == 1 {
		// Single domain case (backward compatibility)
		certFile = filepath.Join(certDir, domains[0]+".crt")
		keyFile = filepath.Join(certDir, domains[0]+".key")
	} else {
		// Multiple domains case - join domain names with underscore
		joinedName := strings.Join(domains, "_")
		certFile = filepath.Join(certDir, joinedName+".crt")
		keyFile = filepath.Join(certDir, joinedName+".key")
	}

	certificate, err := s.store.LoadCertificate(certFile)
	if err != nil {
		log.Printf("Load existing certificate: %v", err)
	}

	if certificate == nil || s.CertificateNeedsRenewal(certificate) {
		log.Printf("Obtaining certificate for domains: %v", domains)
		if err := s.ObtainOrRenewCertificate(ctx, domains, email, certFile, keyFile); err != nil {
			if errors.Is(err, context.Canceled) {
				return errors.New("operation canceled")
			}
			return fmt.Errorf("failed to obtain/renew certificate: %w", err)
		}
	} else {
		log.Printf("Certificate is valid until %s. No action needed.", certificate.NotAfter.Format(time.RFC3339))
	}

	return nil
}
