package core

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"github.com/sukhajata/authservice/internal/keycloak"
	"github.com/sukhajata/authservice/pkg/jwthelper"
	"github.com/sukhajata/devicetwin/pkg/loggerhelper"
	pb "github.com/sukhajata/ppauth"
	pbLogger "github.com/sukhajata/pplogger"
)

type Service struct {
	keycloakClient    *keycloak.Client
	realmID           string
	keycloakUsername  string
	keycloakPassword  string
	serviceKey        string
	adminRole         string
	installerRole     string
	superuserRole     string
	loggerHelper      loggerhelper.Helper
	verifyKey         *rsa.PublicKey
	dataServiceSecret string
}

func NewService(
	keycloakClient *keycloak.Client,
	realmID string,
	keycloakUsername string,
	keycloakPassword string,
	serviceKey string,
	adminRole string,
	installerRole string,
	superuserRole string,
	loggerHelper loggerhelper.Helper,
	verifyKey *rsa.PublicKey,
	dataServiceSecret string,
) *Service {
	return &Service{
		keycloakClient:    keycloakClient,
		realmID:           realmID,
		keycloakUsername:  keycloakUsername,
		keycloakPassword:  keycloakPassword,
		serviceKey:        serviceKey,
		adminRole:         adminRole,
		installerRole:     installerRole,
		superuserRole:     superuserRole,
		loggerHelper:      loggerHelper,
		verifyKey:         verifyKey,
		dataServiceSecret: dataServiceSecret,
	}
}

// GetToken - get a keycloak token from username and password
func (s *Service) GetToken(req *pb.TokenRequest) (*pb.Token, error) {
	if req.GetUsername() == "" || req.GetPassword() == "" {
		return nil, errors.New("missing username or password")
	}

	token, err := s.keycloakClient.GetKeycloakToken(req.GetUsername(), req.GetPassword(), "react-installer", s.realmID)
	if err != nil {
		return nil, err
	}

	return &pb.Token{
		Token: token,
	}, nil
}

// CreateUser -  create a keycloak user
func (s *Service) CreateUser(token string, req *pb.CreateUserRequest) (*pb.CreateUserResponse, error) {
	// check token is valid
	authRequest := &pb.AuthRequest{
		Token:        token,
		AllowedRoles: []string{s.adminRole, s.superuserRole},
	}
	response, err := s.CheckToken(authRequest)
	if err != nil {
		return nil, err
	} else if response.Result == false {
		return nil, errors.New("invalid token")
	}

	// get keycloak admin token
	adminToken, err := s.keycloakClient.GetKeycloakToken(s.keycloakUsername, s.keycloakPassword, "admin-cli", "master")
	if err != nil {
		s.loggerHelper.LogError("createUser", err.Error(), pbLogger.ErrorMessage_FATAL)
		return nil, fmt.Errorf("failed to get admin token")
	}

	// create keycloak user
	userID, err := s.keycloakClient.CreateKeycloakUser(s.realmID, req.Username, req.Email, req.Password, adminToken)
	if err != nil {
		s.loggerHelper.LogError("createUser", err.Error(), pbLogger.ErrorMessage_SEVERE)
		return nil, fmt.Errorf("failed to create keycloak user")
	}

	// add roles
	for _, v := range req.Roles {
		//get role id
		roleID, err := s.keycloakClient.GetRoleID(s.realmID, v, adminToken)
		if err != nil {
			s.loggerHelper.LogError("createUser", err.Error(), pbLogger.ErrorMessage_SEVERE)
			return nil, fmt.Errorf("failed to get role id")
		}

		kr := keycloak.Role{
			ID:          roleID,
			Name:        v,
			ClientRole:  false,
			Composite:   false,
			ContainerID: s.realmID,
		}
		err = s.keycloakClient.AddRoleToKeycloakUser(s.realmID, userID, kr, adminToken)
		if err != nil {
			s.loggerHelper.LogError("createUser", err.Error(), pbLogger.ErrorMessage_SEVERE)
			return nil, fmt.Errorf("failed to add role %s to user", v)
		}
	}

	return &pb.CreateUserResponse{
		UserId: userID,
	}, nil
}

func (s *Service) DeleteUser(token string, req *pb.DeleteUserRequest) (*pb.DeleteUserResponse, error) {
	authRequest := &pb.AuthRequest{
		Token:        token,
		AllowedRoles: []string{s.adminRole, s.superuserRole},
	}
	response, err := s.CheckToken(authRequest)
	if err != nil {
		return nil, err
	} else if response.Result == false {
		return nil, errors.New("invalid token")
	}

	// get admin token
	adminToken, err := s.keycloakClient.GetKeycloakToken(s.keycloakUsername, s.keycloakPassword, "admin-cli", "master")
	if err != nil {
		s.loggerHelper.LogError("createUser", err.Error(), pbLogger.ErrorMessage_FATAL)
		return nil, fmt.Errorf("failed to get admin token")
	}

	// get user id
	userID, err := s.keycloakClient.GetKeycloakUserID(s.realmID, req.Username, adminToken)
	if err != nil {
		s.loggerHelper.LogError("createUser", err.Error(), pbLogger.ErrorMessage_SEVERE)
		return nil, fmt.Errorf("failed to get userID")
	}

	// delete from keycloak
	err = s.keycloakClient.DeleteKeycloakUser(userID, adminToken)
	if err != nil {
		s.loggerHelper.LogError("createUser", err.Error(), pbLogger.ErrorMessage_SEVERE)
		return nil, fmt.Errorf("failed to get userID")
	}

	return &pb.DeleteUserResponse{
		Response: "OK",
	}, nil

}

// CheckToken - check that a token is valid and has one of required roles
func (s *Service) CheckToken(req *pb.AuthRequest) (*pb.AuthResponse, error) {
	// if the token is the API key then return true
	if req.GetToken() == s.serviceKey {
		return &pb.AuthResponse{
			Result:   true,
			Message:  "OK",
			Username: "service",
		}, nil
	}

	pass, username, message, err := jwthelper.CheckJwt(req.GetToken(), req.GetAllowedRoles(), s.verifyKey)
	if err != nil {
		s.loggerHelper.LogError("checkToken", err.Error(), pbLogger.ErrorMessage_WARNING)

		return &pb.AuthResponse{
			Result:  false,
			Message: err.Error(),
		}, err
	}

	if pass == false {
		s.loggerHelper.LogError("checkToken", "token check failed", pbLogger.ErrorMessage_WARNING)

		return &pb.AuthResponse{
			Result:  false,
			Message: message,
		}, nil
	}

	return &pb.AuthResponse{
		Result:   true,
		Username: username,
		Message:  message,
	}, nil

}

// Get a token to access the data API. Requires a keycloak token
func (s *Service) GetDataAPIToken(keycloakToken string) (string, error) {
	// check that the keycloak token is valid
	authRequest := &pb.AuthRequest{
		Token:        keycloakToken,
		AllowedRoles: []string{s.adminRole, s.installerRole, s.superuserRole},
	}
	response, err := s.CheckToken(authRequest)
	if err != nil {
		return "", err
	} else if response.Result == false {
		return "", errors.New("invalid keycloak token")
	}

	// get a data API token with the user's username
	dataToken, err := jwthelper.GetDataToken(s.dataServiceSecret, response.Username)
	if err != nil {
		return "", err
	}

	return dataToken, nil
}
