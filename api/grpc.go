package api

import (
	"context"
	"errors"
	"github.com/sukhajata/authservice/internal/core"
	"github.com/sukhajata/devicetwin/pkg/authhelper"

	pb "github.com/sukhajata/ppauth"
)

type grpcServer struct {
	coreService *core.Service
	pb.UnimplementedAuthServiceServer
}

func NewGRPCServer(coreService *core.Service) *grpcServer {
	return &grpcServer{
		coreService: coreService,
	}
}

// GetToken -  get a keycloak jwt token
func (s *grpcServer) GetToken(ctx context.Context, req *pb.TokenRequest) (*pb.Token, error) {
	if req.GetUsername() == "" || req.GetPassword() == "" {
		return nil, errors.New("missing username or password")
	}

	return s.coreService.GetToken(req)
}

// CheckAuth - check that a token is valid and has one of required roles
func (s *grpcServer) CheckAuth(ctx context.Context, req *pb.AuthRequest) (*pb.AuthResponse, error) {
	if req.GetToken() == "" {
		return &pb.AuthResponse{
			Result:  false,
			Message: "missing auth token",
		}, nil
	}

	return s.coreService.CheckToken(req)
}

// CreateUser - create a keycloak user
func (s *grpcServer) CreateUser(ctx context.Context, req *pb.CreateUserRequest) (*pb.CreateUserResponse, error) {
	token, err := authhelper.GetTokenFromContext(ctx)
	if err != nil {
		return nil, err
	}

	return s.coreService.CreateUser(token, req)
}

func (s *grpcServer) DeleteUser(ctx context.Context, req *pb.DeleteUserRequest) (*pb.DeleteUserResponse, error) {
	token, err := authhelper.GetTokenFromContext(ctx)
	if err != nil {
		return nil, err
	}

	return s.coreService.DeleteUser(token, req)
}
