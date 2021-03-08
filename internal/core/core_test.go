package core

import (
	"crypto/rsa"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	"github.com/sukhajata/authservice/mocks"
	pb "github.com/sukhajata/ppauth"
	pbLogger "github.com/sukhajata/pplogger"
	"testing"
)

var (
	apiKey = "2e0129ejje21e12e"
)

func setup(mockCtrl *gomock.Controller) (*Service, *mocks.MockClient, *mocks.MockHelper) {
	mockKeycloakClient := mocks.NewMockClient(mockCtrl)
	mockLoggerHelper := mocks.NewMockHelper(mockCtrl)
	key := &rsa.PublicKey{}
	coreService := NewService(
		mockKeycloakClient,
		"devpower",
		"admin",
		"test",
		apiKey,
		"powerpilot-admin",
		"powerpilot-installer",
		"powerpilot-superuser",
		mockLoggerHelper,
		key,
		"secret",
	)

	return coreService, mockKeycloakClient, mockLoggerHelper
}

func TestService_GetToken(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
	coreService, keycloakMock, _ := setup(mockCtrl)

	// setup
	req := &pb.TokenRequest{
		Username: "bob",
		Password: "fluffy",
	}
	token := "123"

	// expect
	keycloakMock.EXPECT().GetKeycloakToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(token, nil).Times(1)

	// call
	result, err := coreService.GetToken(req)
	require.NoError(t, err)
	require.Equal(t, token, result.Token)
}

func TestService_CheckToken(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
	coreService, _, mockLoggerHelper := setup(mockCtrl)

	// setup
	token := "123"
	req := &pb.AuthRequest{
		Token:        token,
		AllowedRoles: []string{"powerpilot-admin"},
	}

	// expect
	mockLoggerHelper.EXPECT().LogError(gomock.Any(), gomock.Any(), pbLogger.ErrorMessage_WARNING)

	// call
	result, err := coreService.CheckToken(req)
	require.NoError(t, err)
	require.Equal(t, "token contains an invalid number of segments", result.Message)
}

func TestService_CreateUser(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
	coreService, mockKeycloakClient, _ := setup(mockCtrl)

	// setup
	userID := "ling"
	req := &pb.CreateUserRequest{
		Username: "bob",
		Email:    "bob@example.com",
		Password: "123",
		Roles:    []string{"powerpilot-admin"},
	}

	// expect
	mockKeycloakClient.EXPECT().GetKeycloakToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(apiKey, nil).Times(1)
	mockKeycloakClient.EXPECT().CreateKeycloakUser(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(userID, nil)
	mockKeycloakClient.EXPECT().GetRoleID(gomock.Any(), gomock.Any(), gomock.Any()).Return("abcd", nil)
	mockKeycloakClient.EXPECT().AddRoleToKeycloakUser(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

	// call
	result, err := coreService.CreateUser(apiKey, req)
	require.NoError(t, err)
	require.Equal(t, userID, result.UserId)
}

func TestService_DeleteUser(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
	coreService, mockKeycloakClient, _ := setup(mockCtrl)

	// setup
	userID := "ling"
	req := &pb.DeleteUserRequest{
		Username: "bob",
	}

	// expect
	mockKeycloakClient.EXPECT().GetKeycloakToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(apiKey, nil).Times(1)
	mockKeycloakClient.EXPECT().GetKeycloakUserID(gomock.Any(), gomock.Any(), gomock.Any()).Return(userID, nil)
	mockKeycloakClient.EXPECT().DeleteKeycloakUser(gomock.Any(), gomock.Any()).Return(nil)

	// call
	result, err := coreService.DeleteUser(apiKey, req)
	require.NoError(t, err)
	require.Equal(t, "OK", result.Response)
}

func TestService_GetDataAPIToken(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
	coreService, _, _ := setup(mockCtrl)

	// call
	result, err := coreService.GetDataAPIToken(apiKey)
	require.NoError(t, err)
	require.Equal(t, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoid2ViX3VzZXIiLCJ1c2VyIjoic2VydmljZSJ9.ZDi2ORfuTp3J-lIDHE6IWE7IDxHCpn5DfAff_01ASZ4", result)
}
