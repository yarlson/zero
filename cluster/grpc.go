package cluster

import (
	"context"
	"time"

	pb "github.com/yarlson/zero/cluster/proto"
)

type grpcServer struct {
	pb.UnimplementedClusterServiceServer
	manager *Manager
}

func (s *grpcServer) SyncChallenge(ctx context.Context, req *pb.Challenge) (*pb.ChallengeResponse, error) {
	token := &ChallengeToken{
		Token:     req.Token,
		KeyAuth:   req.KeyAuth,
		ExpiresAt: time.Unix(req.ExpiresAt, 0),
	}

	if err := s.manager.DistributeChallenge(token); err != nil {
		return &pb.ChallengeResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	return &pb.ChallengeResponse{Success: true}, nil
}

func (s *grpcServer) SyncCertificate(ctx context.Context, req *pb.Certificate) (*pb.CertificateResponse, error) {
	bundle := &CertificateBundle{
		Domain:      req.Domain,
		Certificate: req.Certificate,
		PrivateKey:  req.PrivateKey,
		UpdatedAt:   time.Unix(req.UpdatedAt, 0),
	}

	if err := s.manager.DistributeCertificate(bundle); err != nil {
		return &pb.CertificateResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	return &pb.CertificateResponse{Success: true}, nil
}

func (s *grpcServer) HealthCheck(ctx context.Context, req *pb.HealthCheckRequest) (*pb.HealthCheckResponse, error) {
	return &pb.HealthCheckResponse{
		Healthy: true,
		Status:  "ok",
	}, nil
}
