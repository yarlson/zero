package cluster

import (
	"context"
	"fmt"
	"log"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/hashicorp/memberlist"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/yarlson/zero/cluster/proto"
)

type Manager struct {
	config     *Config
	memberlist *memberlist.Memberlist
	instances  map[string]*Instance
	challenges map[string]*ChallengeToken
	certStore  *CertificateStore

	// Leader election
	isLeader    bool
	leaderID    string
	leaderMutex sync.RWMutex

	// gRPC server for internode communication
	grpcServer *grpc.Server

	// Channels for coordination
	shutdownCh   chan struct{}
	challengeCh  chan *ChallengeToken
	certUpdateCh chan *CertificateBundle
}

func NewManager(cfg *Config) (*Manager, error) {
	if cfg.InstanceID == "" {
		cfg.InstanceID = GenerateInstanceID()
	}

	m := &Manager{
		config:       cfg,
		instances:    make(map[string]*Instance),
		challenges:   make(map[string]*ChallengeToken),
		shutdownCh:   make(chan struct{}),
		challengeCh:  make(chan *ChallengeToken, 100),
		certUpdateCh: make(chan *CertificateBundle, 100),
	}

	if err := m.initialize(); err != nil {
		return nil, fmt.Errorf("initialize cluster manager: %w", err)
	}

	return m, nil
}

func (m *Manager) initialize() error {
	// Initialize memberlist for cluster membership
	mlConfig := memberlist.DefaultLocalConfig()
	mlConfig.Name = m.config.InstanceID
	mlConfig.BindAddr = m.config.BindAddress

	ml, err := memberlist.Create(mlConfig)
	if err != nil {
		return fmt.Errorf("create memberlist: %w", err)
	}
	m.memberlist = ml

	// Initialize certificate store
	m.certStore = NewCertificateStore(m.config.StateDir)

	// Start gRPC server
	if err := m.startGRPCServer(); err != nil {
		return fmt.Errorf("start gRPC server: %w", err)
	}

	return nil
}

func (m *Manager) Start(ctx context.Context) error {
	// Join cluster if seed nodes are provided
	if len(m.config.SeedNodes) > 0 {
		if _, err := m.memberlist.Join(m.config.SeedNodes); err != nil {
			log.Printf("Failed to join cluster: %v", err)
		}
	}

	// Start background tasks
	go m.runLeaderElection(ctx)
	go m.runHealthCheck(ctx)
	go m.processChallenges(ctx)
	go m.processCertificateUpdates(ctx)

	return nil
}

func (m *Manager) Stop() error {
	close(m.shutdownCh)

	if err := m.memberlist.Leave(time.Second * 5); err != nil {
		log.Printf("Error leaving cluster: %v", err)
	}

	m.grpcServer.GracefulStop()
	return nil
}

// IsLeader returns whether this instance is the cluster leader
func (m *Manager) IsLeader() bool {
	m.leaderMutex.RLock()
	defer m.leaderMutex.RUnlock()
	return m.isLeader
}

// DistributeChallenge shares an ACME challenge token with all instances
func (m *Manager) DistributeChallenge(token *ChallengeToken) error {
	m.challengeCh <- token
	return nil
}

// DistributeCertificate shares a new certificate with all instances
func (m *Manager) DistributeCertificate(bundle *CertificateBundle) error {
	m.certUpdateCh <- bundle
	return nil
}

// runLeaderElection implements a simple leader election using memberlist
func (m *Manager) runLeaderElection(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			members := m.memberlist.Members()
			if len(members) == 0 {
				continue
			}

			// Sort members by ID to ensure consistent leader selection
			sort.Slice(members, func(i, j int) bool {
				return members[i].Name < members[j].Name
			})

			// The first member in the sorted list becomes leader
			leader := members[0].Name

			m.leaderMutex.Lock()
			m.isLeader = leader == m.config.InstanceID
			m.leaderID = leader
			m.leaderMutex.Unlock()
		}
	}
}

// runHealthCheck periodically checks the health of cluster members
func (m *Manager) runHealthCheck(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			members := m.memberlist.Members()
			for _, member := range members {
				if member.Name == m.config.InstanceID {
					continue
				}

				// Update instance status
				m.updateInstanceStatus(member)
			}
		}
	}
}

// processChallenges handles incoming ACME challenge tokens
func (m *Manager) processChallenges(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case token := <-m.challengeCh:
			// Store challenge locally
			m.challenges[token.Token] = token

			// Distribute to other nodes if we're the leader
			if m.IsLeader() {
				if err := m.syncChallengeToNodes(ctx, token); err != nil {
					log.Printf("Error syncing challenge: %v", err)
				}
			}
		}
	}
}

// processCertificateUpdates handles certificate updates
func (m *Manager) processCertificateUpdates(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case bundle := <-m.certUpdateCh:
			// Store certificate locally
			if err := m.certStore.StoreCertificate(bundle); err != nil {
				log.Printf("Error storing certificate: %v", err)
				continue
			}

			// Distribute to other nodes if we're the leader
			if m.IsLeader() {
				if err := m.syncCertificateToNodes(ctx, bundle); err != nil {
					log.Printf("Error syncing certificate: %v", err)
				}
			}
		}
	}
}

// startGRPCServer initializes and starts the gRPC server
func (m *Manager) startGRPCServer() error {
	lis, err := net.Listen("tcp", m.config.BindAddress)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	var opts []grpc.ServerOption
	if m.config.TLSConfig != nil {
		opts = append(opts, grpc.Creds(credentials.NewTLS(m.config.TLSConfig)))
	}

	m.grpcServer = grpc.NewServer(opts...)
	pb.RegisterClusterServiceServer(m.grpcServer, &grpcServer{manager: m})

	go func() {
		if err := m.grpcServer.Serve(lis); err != nil {
			log.Printf("Failed to serve gRPC: %v", err)
		}
	}()

	return nil
}

// updateInstanceStatus updates the status of a cluster member
func (m *Manager) updateInstanceStatus(member *memberlist.Node) {
	instance := &Instance{
		ID:       member.Name,
		Address:  member.Addr.String(),
		LastSeen: time.Now(),
		Status:   StatusActive,
	}

	// Create context with timeout for the gRPC connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := m.checkInstanceHealth(ctx, instance); err != nil {
		instance.Status = StatusInactive
	}

	m.instances[instance.ID] = instance
}

// checkInstanceHealth checks if an instance is healthy via gRPC
func (m *Manager) checkInstanceHealth(ctx context.Context, instance *Instance) error {
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}
	conn, err := grpc.NewClient(instance.Address, opts...)
	if err != nil {
		return fmt.Errorf("connect to instance: %w", err)
	}
	defer func() { _ = conn.Close() }()

	client := pb.NewClusterServiceClient(conn)
	_, err = client.HealthCheck(ctx, &pb.HealthCheckRequest{
		InstanceId: m.config.InstanceID,
	})
	if err != nil {
		return fmt.Errorf("health check: %w", err)
	}

	return nil
}

// syncChallengeToNodes distributes an ACME challenge token to all cluster nodes
func (m *Manager) syncChallengeToNodes(ctx context.Context, token *ChallengeToken) error {
	members := m.memberlist.Members()
	for _, member := range members {
		if member.Name == m.config.InstanceID {
			continue
		}

		if err := m.syncChallengeToNode(ctx, member, token); err != nil {
			log.Printf("Failed to sync challenge to node %s: %v", member.Name, err)
		}
	}
	return nil
}

// syncChallengeToNode syncs challenge to a single node
func (m *Manager) syncChallengeToNode(ctx context.Context, member *memberlist.Node, token *ChallengeToken) error {
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}
	conn, err := grpc.NewClient(member.Addr.String(), opts...)
	if err != nil {
		return fmt.Errorf("connect to node: %w", err)
	}
	defer func() { _ = conn.Close() }()

	client := pb.NewClusterServiceClient(conn)

	req := &pb.Challenge{
		Token:     token.Token,
		KeyAuth:   token.KeyAuth,
		ExpiresAt: token.ExpiresAt.Unix(),
	}

	resp, err := client.SyncChallenge(ctx, req)
	if err != nil {
		return fmt.Errorf("sync challenge: %w", err)
	}

	if !resp.Success {
		return fmt.Errorf("node reported error: %s", resp.Error)
	}

	return nil
}

// syncCertificateToNodes distributes a certificate bundle to all cluster nodes
func (m *Manager) syncCertificateToNodes(ctx context.Context, bundle *CertificateBundle) error {
	members := m.memberlist.Members()
	for _, member := range members {
		if member.Name == m.config.InstanceID {
			continue
		}

		if err := m.syncCertificateToNode(ctx, member, bundle); err != nil {
			log.Printf("Failed to sync certificate to node %s: %v", member.Name, err)
		}
	}
	return nil
}

// syncCertificateToNode syncs certificate to a single node
func (m *Manager) syncCertificateToNode(ctx context.Context, member *memberlist.Node, bundle *CertificateBundle) error {
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}
	conn, err := grpc.NewClient(member.Addr.String(), opts...)
	if err != nil {
		return fmt.Errorf("connect to node: %w", err)
	}
	defer func() { _ = conn.Close() }()

	client := pb.NewClusterServiceClient(conn)

	req := &pb.Certificate{
		Domain:      bundle.Domain,
		Certificate: bundle.Certificate,
		PrivateKey:  bundle.PrivateKey,
		UpdatedAt:   bundle.UpdatedAt.Unix(),
	}

	resp, err := client.SyncCertificate(ctx, req)
	if err != nil {
		return fmt.Errorf("sync certificate: %w", err)
	}

	if !resp.Success {
		return fmt.Errorf("node reported error: %s", resp.Error)
	}

	return nil
}
