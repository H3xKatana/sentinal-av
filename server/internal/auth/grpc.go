package auth

import (
	"context"
	"errors"
	"strings"

	"github.com/0xA1M/sentinel-server/internal/models"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// GRPCAuthInterceptor is a gRPC unary interceptor for authentication
func (s *Service) GRPCAuthInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	// Skip authentication for public methods
	publicMethods := map[string]bool{
		"/sentinel.AgentService/RegisterAgent": true,
		"/sentinel.AgentService/GetSignatures": true,
	}

	if publicMethods[info.FullMethod] {
		return handler(ctx, req)
	}

	// Extract token from context metadata
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "Missing metadata")
	}

	tokenStrings := md["authorization"]
	if len(tokenStrings) == 0 {
		tokenStrings = md["Authorization"] // Some clients send capitalized header
	}
	if len(tokenStrings) == 0 {
		return nil, status.Error(codes.Unauthenticated, "Missing authorization token")
	}

	authHeader := tokenStrings[0]
	if authHeader == "" {
		return nil, status.Error(codes.Unauthenticated, "Empty authorization header")
	}

	// Expect format: "Bearer <token>"
	tokenParts := strings.Split(authHeader, " ")
	if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
		return nil, status.Error(codes.Unauthenticated, "Authorization header must be in format 'Bearer <token>'")
	}

	tokenString := tokenParts[1]

	// Validate the token
	user, err := s.ValidateToken(tokenString)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return nil, status.Error(codes.Unauthenticated, "User not found")
		}
		return nil, status.Error(codes.Unauthenticated, "Invalid token")
	}

	// Add user to context
	newCtx := context.WithValue(ctx, UserContextKey, user)

	return handler(newCtx, req)
}

// GetAgentFromContext retrieves the authenticated agent from request context
// This is a helper for agent-specific authentication
func GetAgentFromContext(ctx context.Context) (*models.Agent, error) {
	agent, ok := ctx.Value("agent").(*models.Agent)
	if !ok || agent == nil {
		return nil, errors.New("agent not found in context")
	}
	return agent, nil
}
