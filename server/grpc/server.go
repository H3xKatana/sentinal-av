package grpc

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/0xA1M/sentinel-server/grpc/pb"
	"github.com/0xA1M/sentinel-server/internal/auth"
	"github.com/0xA1M/sentinel-server/internal/models"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
)

// Server represents the gRPC server
type Server struct {
	DB      *gorm.DB
	AuthSvc *auth.Service
	pb.UnimplementedAgentServiceServer
	grpcServer *grpc.Server
	lis        net.Listener
}

// NewServer creates a new gRPC server instance
func NewServer(db *gorm.DB, authSvc *auth.Service) *Server {
	return &Server{
		DB:      db,
		AuthSvc: authSvc,
	}
}

// RegisterAgent handles agent registration requests
func (s *Server) RegisterAgent(ctx context.Context, req *pb.RegisterAgentRequest) (*pb.RegisterAgentResponse, error) {
	// Check if agent already exists based on the provided information
	var existingAgent models.Agent
	result := s.DB.Where("name = ? OR public_key = ?", req.AgentName, req.PublicKey).First(&existingAgent)

	if result.Error == nil {
		// Agent already exists
		return &pb.RegisterAgentResponse{
			AgentId: existingAgent.AgentID,
			Token:   "dummy-token", // In a real implementation, generate a proper token
			Status:  "success",
			Message: "Agent already registered",
		}, nil
	} else if result.Error != gorm.ErrRecordNotFound {
		// Database error
		return nil, status.Error(codes.Internal, "Database error")
	}

	// Create new agent
	agent := models.Agent{
		Name:         req.AgentName,
		Hostname:     req.Hostname,
		Platform:     req.Platform,
		Version:      req.Version,
		IPAddress:    req.IpAddress,
		PublicKey:    req.PublicKey,
		LastSeen:     &[]time.Time{time.Now()}[0],
		IsActive:     true,
		Quarantine:   false,
		RegisteredAt: time.Now(),
	}

	result = s.DB.Create(&agent)
	if result.Error != nil {
		return nil, status.Error(codes.Internal, "Failed to register agent")
	}

	// Generate a proper agent ID
	agent.AgentID = fmt.Sprintf("agent-%d-%d", time.Now().Unix(), agent.ID)
	result = s.DB.Save(&agent)
	if result.Error != nil {
		return nil, status.Error(codes.Internal, "Failed to save agent ID")
	}

	return &pb.RegisterAgentResponse{
		AgentId: agent.AgentID,
		Token:   "dummy-token", // In a real implementation, generate a proper token
		Status:  "success",
		Message: "Agent registered successfully",
	}, nil
}

// SendScanResults handles scan results from agents
func (s *Server) SendScanResults(ctx context.Context, req *pb.ScanResultsRequest) (*pb.ScanResultsResponse, error) {
	// Find the agent by ID
	var agent models.Agent
	result := s.DB.Where("agent_id = ?", req.AgentId).First(&agent)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, status.Error(codes.NotFound, "Agent not found")
		}
		return nil, status.Error(codes.Internal, "Database error")
	}

	// Convert protobuf scan results to model
	scanResult := models.ScanResult{
		AgentID:   agent.ID,
		ScanType:  req.ScanType,
		FilePaths: make([]string, len(req.FilePaths)),
		ScanTime:  time.Unix(req.ScanTime, 0),
		Duration:  req.Duration,
		Status:    req.Status,
	}

	copy(scanResult.FilePaths, req.FilePaths)

	result = s.DB.Create(&scanResult)
	if result.Error != nil {
		return nil, status.Error(codes.Internal, "Failed to save scan result")
	}

	// Create threat records if any
	for _, threat := range req.Threats {
		threatRecord := models.Threat{
			ScanResultID: scanResult.ID,
			FilePath:     threat.FilePath,
			ThreatType:   threat.ThreatType,
			ThreatName:   threat.ThreatName,
			Severity:     threat.Severity,
			ActionTaken:  threat.ActionTaken,
			CreatedAt:    time.Now(),
		}
		s.DB.Create(&threatRecord)
	}

	return &pb.ScanResultsResponse{
		Status:  "success",
		Message: "Scan results received",
	}, nil
}

// GetSignatures returns the latest signatures for agent sync
func (s *Server) GetSignatures(ctx context.Context, req *pb.GetSignaturesRequest) (*pb.GetSignaturesResponse, error) {
	var signatures []models.Signature
	result := s.DB.Where("status = ?", "active").Find(&signatures)
	if result.Error != nil {
		return nil, status.Error(codes.Internal, "Failed to retrieve signatures")
	}

	pbSignatures := make([]*pb.Signature, len(signatures))
	for i, sig := range signatures {
		pbSignatures[i] = &pb.Signature{
			Id:          uint32(sig.ID),
			Name:        sig.Name,
			Type:        sig.Type,
			Content:     sig.Content,
			HashType:    sig.HashType,
			ThreatType:  sig.ThreatType,
			Description: sig.Description,
			Version:     sig.Version,
			Status:      sig.Status,
			UpdatedAt:   sig.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"), // ISO 8601 format
		}
	}

	return &pb.GetSignaturesResponse{
		Signatures:     pbSignatures,
		SignatureCount: int32(len(signatures)),
		SyncTime:       time.Now().Format("2006-01-02T15:04:05Z07:00"), // ISO 8601 format
		Status:         "success",
	}, nil
}

// SendEvent handles security events from agents
func (s *Server) SendEvent(ctx context.Context, req *pb.EventRequest) (*pb.EventResponse, error) {
	// Find the agent by ID
	var agent models.Agent
	result := s.DB.Where("agent_id = ?", req.AgentId).First(&agent)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, status.Error(codes.NotFound, "Agent not found")
		}
		return nil, status.Error(codes.Internal, "Database error")
	}

	// Create the event
	event := models.Event{
		AgentID:     agent.ID,
		EventType:   req.EventType,
		EventSource: req.EventSource,
		Description: req.Description,
		Severity:    req.Severity,
		Data:        req.Data,
		Timestamp:   time.Unix(req.Timestamp, 0),
	}

	result = s.DB.Create(&event)
	if result.Error != nil {
		return nil, status.Error(codes.Internal, "Failed to save event")
	}

	return &pb.EventResponse{
		Status:  "success",
		Message: "Event received",
	}, nil
}

// Heartbeat handles agent heartbeat requests
func (s *Server) Heartbeat(ctx context.Context, req *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error) {
	// Find the agent by ID
	var agent models.Agent
	result := s.DB.Where("agent_id = ?", req.AgentId).First(&agent)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, status.Error(codes.NotFound, "Agent not found")
		}
		return nil, status.Error(codes.Internal, "Database error")
	}

	// Update last seen time
	now := time.Now()
	agent.LastSeen = &now
	agent.UpdatedAt = now

	result = s.DB.Save(&agent)
	if result.Error != nil {
		return nil, status.Error(codes.Internal, "Failed to update agent heartbeat")
	}

	// Check if agent is in quarantine mode
	quarantineMode := agent.Quarantine

	// For now, return an empty command list
	commands := []*pb.Command{}

	return &pb.HeartbeatResponse{
		Status:         "success",
		Message:        "Heartbeat received",
		ServerTime:     now.Unix(),
		QuarantineMode: quarantineMode,
		Commands:       commands,
	}, nil
}

// Start starts the gRPC server on the specified port
func (s *Server) Start(port string) error {
	var opts []grpc.ServerOption

	// Add authentication interceptor
	opts = append(opts, grpc.UnaryInterceptor(s.AuthSvc.GRPCAuthInterceptor))

	// Add TLS if enabled
	if certFile := getEnv("GRPC_CERT_FILE", ""); certFile != "" {
		if keyFile := getEnv("GRPC_KEY_FILE", ""); keyFile != "" {
			creds, err := credentials.NewServerTLSFromFile(certFile, keyFile)
			if err != nil {
				log.Printf("Failed to load TLS certificates: %v", err)
				return err
			}
			opts = append(opts, grpc.Creds(creds))
			log.Println("gRPC server configured with TLS")
		}
	}

	grpcServer := grpc.NewServer(opts...)
	pb.RegisterAgentServiceServer(grpcServer, s)

	s.grpcServer = grpcServer

	lis, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return fmt.Errorf("failed to listen: %v", err)
	}
	s.lis = lis

	log.Printf("gRPC server listening on port %s", port)
	if err := grpcServer.Serve(lis); err != nil && err != grpc.ErrServerStopped {
		return fmt.Errorf("failed to serve: %v", err)
	}

	return nil
}

// Stop gracefully stops the gRPC server
func (s *Server) Stop() {
	if s.grpcServer != nil {
		log.Println("Gracefully stopping gRPC server...")
		s.grpcServer.GracefulStop() // This will stop the server gracefully
		log.Println("gRPC server stopped")
	}
	if s.lis != nil {
		// Close listener if not already closed by GracefulStop
		s.lis.Close()
	}
}

// RegisterAgentServiceServer registers the agent service with the gRPC server
func RegisterAgentServiceServer(srv *grpc.Server, service pb.AgentServiceServer) {
	pb.RegisterAgentServiceServer(srv, service)
}

// getEnv retrieves an environment variable or returns a default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
