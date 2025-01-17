package cluster

import (
	"crypto/tls"
	"time"
)

// Instance represents a node in the cluster
type Instance struct {
	ID       string
	Address  string
	IsLeader bool
	LastSeen time.Time
	Status   InstanceStatus
}

type InstanceStatus string

const (
	StatusActive   InstanceStatus = "active"
	StatusInactive InstanceStatus = "inactive"
)

// Config holds configuration for cluster operations
type Config struct {
	// Unique identifier for this instance
	InstanceID string
	// Address for cluster communication
	BindAddress string
	// List of seed nodes to join cluster
	SeedNodes []string
	// TLS configuration for secure communication
	TLSConfig *tls.Config
	// Directory for cluster state
	StateDir string
}

// ChallengeToken represents an ACME HTTP-01 challenge
type ChallengeToken struct {
	Token     string
	KeyAuth   string
	ExpiresAt time.Time
}

// CertificateBundle contains certificate data for distribution
type CertificateBundle struct {
	Domain      string
	Certificate []byte
	PrivateKey  []byte
	UpdatedAt   time.Time
}
