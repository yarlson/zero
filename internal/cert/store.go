package cert

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"sync"
)

type Store struct {
	challenges  map[string]string
	challengeMu sync.RWMutex
}

func NewStore() *Store {
	return &Store{
		challenges: make(map[string]string),
	}
}

func (s *Store) SaveCertificate(filename string, certBytes [][]byte) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("create certificate file: %w", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close certificate file: %w", closeErr)
		}
	}()

	for _, cert := range certBytes {
		if err := pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: cert}); err != nil {
			return fmt.Errorf("encode certificate: %w", err)
		}
	}
	return nil
}

func (s *Store) SavePrivateKey(filename string, privateKey crypto.PrivateKey) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("create private key file: %w", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close private key file: %w", closeErr)
		}
	}()

	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("marshal private key: %w", err)
	}
	return pem.Encode(file, &pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyBytes})
}

func (s *Store) LoadCertificate(filename string) (*x509.Certificate, error) {
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

func (s *Store) StoreChallenge(token, response string) {
	s.challengeMu.Lock()
	defer s.challengeMu.Unlock()
	s.challenges[token] = response
}

func (s *Store) GetChallengeResponse(token string) (string, bool) {
	s.challengeMu.RLock()
	response, exists := s.challenges[token]
	s.challengeMu.RUnlock()

	if exists {
		go func(tokenToDelete string) {
			s.challengeMu.Lock()
			delete(s.challenges, tokenToDelete)
			s.challengeMu.Unlock()
		}(token)
	}

	return response, exists
}
