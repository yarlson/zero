package certificates

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	renewBeforeDays = 30
)

type ZeroSSLService interface {
	ObtainCertificate(ctx context.Context, domain, email string, challengeHandler func(token, response string)) ([][]byte, crypto.PrivateKey, error)
}

type Service struct {
	zeroSSLService ZeroSSLService
	challenges     map[string]string
	challengeMu    sync.RWMutex
}

func New(zeroSSLService ZeroSSLService) *Service {
	return &Service{
		zeroSSLService: zeroSSLService,
		challenges:     make(map[string]string),
	}
}

func (s *Service) saveCertificate(filename string, certBytes [][]byte) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("create certificate file: %w", err)
	}
	defer file.Close()

	for _, cert := range certBytes {
		if err := pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: cert}); err != nil {
			return fmt.Errorf("encode certificate: %w", err)
		}
	}
	return nil
}

func (s *Service) savePrivateKey(filename string, privateKey crypto.PrivateKey) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("create private key file: %w", err)
	}
	defer file.Close()

	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("marshal private key: %w", err)
	}
	return pem.Encode(file, &pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyBytes})
}

func (s *Service) LoadCertificate(filename string) (*x509.Certificate, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("read certificate file: %w", err)
	}

	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			return x509.ParseCertificate(block.Bytes)
		}
		data = rest
	}
	return nil, fmt.Errorf("no certificate found in %s", filename)
}

func (s *Service) CertificateNeedsRenewal(cert *x509.Certificate) bool {
	return time.Now().Add(renewBeforeDays * 24 * time.Hour).After(cert.NotAfter)
}

func (s *Service) ObtainOrRenewCertificate(ctx context.Context, domain, email, certFile, keyFile string) error {
	certs, privateKey, err := s.zeroSSLService.ObtainCertificate(ctx, domain, email, s.StoreChallenge)
	if err != nil {
		return fmt.Errorf("obtain certificate: %w", err)
	}

	if err := s.saveCertificate(certFile, certs); err != nil {
		return fmt.Errorf("save certificate: %w", err)
	}
	if err := s.savePrivateKey(keyFile, privateKey); err != nil {
		return fmt.Errorf("save private key: %w", err)
	}

	log.Printf("Certificate saved to: %s", certFile)
	log.Printf("Private key saved to: %s", keyFile)
	return nil
}

func (s *Service) StoreChallenge(token, response string) {
	s.challengeMu.Lock()
	defer s.challengeMu.Unlock()
	s.challenges[token] = response
}

func (s *Service) GetChallengeResponse(token string) (string, bool) {
	s.challengeMu.RLock()
	defer s.challengeMu.RUnlock()
	response, exists := s.challenges[token]
	return response, exists
}

func (s *Service) CheckCertificate(ctx context.Context, domain, email, certDir string) error {
	certFile := filepath.Join(certDir, domain+".crt")
	keyFile := filepath.Join(certDir, domain+".key")

	cert, err := s.LoadCertificate(certFile)
	if err != nil {
		log.Printf("Load existing certificate: %v", err)
	}

	if cert == nil || s.CertificateNeedsRenewal(cert) {
		log.Printf("Obtaining certificate for %s", domain)
		if err := s.ObtainOrRenewCertificate(ctx, domain, email, certFile, keyFile); err != nil {
			if errors.Is(err, context.Canceled) {
				return errors.New("operation canceled")
			}
			return fmt.Errorf("failed to obtain/renew certificate: %w", err)
		}
	} else {
		log.Printf("Certificate is valid until %s. No action needed.", cert.NotAfter.Format(time.RFC3339))
	}

	return nil
}
