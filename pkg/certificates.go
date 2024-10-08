package pkg

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"time"
)

const (
	renewBeforeDays = 30
)

type CertificateService struct {
	zeroSSLService *ZeroSSLService
}

func NewCertificateService(zeroSSLService *ZeroSSLService) *CertificateService {
	return &CertificateService{
		zeroSSLService: zeroSSLService,
	}
}

func (s *CertificateService) saveCertificate(filename string, certBytes [][]byte) error {
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

func (s *CertificateService) savePrivateKey(filename string, privateKey crypto.PrivateKey) error {
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

func (s *CertificateService) LoadCertificate(filename string) (*x509.Certificate, error) {
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

func (s *CertificateService) certificateNeedsRenewal(cert *x509.Certificate) bool {
	return time.Now().Add(renewBeforeDays * 24 * time.Hour).After(cert.NotAfter)
}

func (s *CertificateService) ShouldObtainCertificate(action string, cert *x509.Certificate) bool {
	switch action {
	case "issue":
		return true
	case "renew":
		if cert == nil {
			log.Fatal("No existing certificate to renew.")
		}
		return true
	case "auto":
		return cert == nil || s.certificateNeedsRenewal(cert)
	}
	return false
}

func (s *CertificateService) ObtainOrRenewCertificate(ctx context.Context, domain, email, certFile, keyFile string) error {
	_, certs, privateKey, err := s.zeroSSLService.ObtainCertificate(ctx, domain, email)
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
