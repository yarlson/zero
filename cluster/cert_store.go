package cluster

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type CertificateStore struct {
	dir   string
	cache map[string]*CertificateBundle
	mutex sync.RWMutex
}

func NewCertificateStore(dir string) *CertificateStore {
	return &CertificateStore{
		dir:   dir,
		cache: make(map[string]*CertificateBundle),
	}
}

func (s *CertificateStore) StoreCertificate(bundle *CertificateBundle) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Store in memory cache
	s.cache[bundle.Domain] = bundle

	// Persist to disk
	bundleFile := filepath.Join(s.dir, fmt.Sprintf("%s.json", bundle.Domain))
	data, err := json.Marshal(bundle)
	if err != nil {
		return fmt.Errorf("marshal certificate bundle: %w", err)
	}

	if err := os.WriteFile(bundleFile, data, 0600); err != nil {
		return fmt.Errorf("write certificate bundle: %w", err)
	}

	return nil
}

func (s *CertificateStore) GetCertificate(domain string) (*CertificateBundle, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	if bundle, ok := s.cache[domain]; ok {
		return bundle, nil
	}

	// Try loading from disk
	bundleFile := filepath.Join(s.dir, fmt.Sprintf("%s.json", domain))
	data, err := os.ReadFile(bundleFile)
	if err != nil {
		return nil, fmt.Errorf("read certificate bundle: %w", err)
	}

	var bundle CertificateBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil, fmt.Errorf("unmarshal certificate bundle: %w", err)
	}

	s.cache[domain] = &bundle
	return &bundle, nil
}
