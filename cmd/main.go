package main

import (
	"fmt"
	"github.com/sukhajata/authservice/api"
	"github.com/sukhajata/authservice/internal/core"
	"github.com/sukhajata/devicetwin/pkg/errorhelper"
	"github.com/sukhajata/devicetwin/pkg/grpchelper"
	"github.com/sukhajata/devicetwin/pkg/loggerhelper"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/sukhajata/authservice/internal/keycloak"

	pb "github.com/sukhajata/ppauth"
	pbLogger "github.com/sukhajata/pplogger"
	"google.golang.org/grpc"
)

var (
	adminRole               = os.Getenv("rolePowerpilotAdmin")
	installerRole           = os.Getenv("rolePowerpilotInstaller")
	superUserRole           = os.Getenv("rolePowerpilotSuperuser")
	port                    = os.Getenv("authServicePort")
	httpPort                = os.Getenv("httpPort")
	grpcLoggerServerAddress = os.Getenv("grpcLoggerServiceAddress")
	serviceKey              = os.Getenv("serviceKey")
	keycloakURL             = os.Getenv("keycloakUrl")
	keycloakUsername        = os.Getenv("keycloakUsername")
	keycloakPassword        = os.Getenv("keycloakPassword")
	realmID                 = os.Getenv("realmId")
	dataServiceSecret       = os.Getenv("dataServiceSecret")

	grpcLoggerClient pbLogger.LoggerServiceClient
)

func main() {
	for _, pair := range os.Environ() {
		fmt.Println(pair)
	}

	// logger client
	conn, err := grpchelper.ConnectGRPC(grpcLoggerServerAddress)
	errorhelper.PanicOnError(err)
	defer func() {
		err := conn.Close()
		if err != nil {
			fmt.Println(err)
		}
	}()
	grpcLoggerClient = pbLogger.NewLoggerServiceClient(conn)

	loggerHelper := loggerhelper.NewHelper(grpcLoggerClient, "auth-service")

	// keycloak client
	httpClient := &http.Client{}
	keycloakClient := keycloak.NewClient(keycloakURL, realmID, httpClient)
	// get public key
	verifyKey, err := keycloakClient.GetVerifyKey(keycloakUsername, keycloakPassword)
	errorhelper.PanicOnError(err)

	// core service
	coreService := core.NewService(
		keycloakClient,
		realmID,
		keycloakUsername,
		keycloakPassword,
		serviceKey,
		adminRole,
		installerRole,
		superUserRole,
		loggerHelper,
		verifyKey,
		dataServiceSecret,
	)

	// HTTP server
	httpServer := api.NewHTTPServer(coreService, loggerHelper, httpPort)

	// GRPC server
	lis, err := net.Listen("tcp", fmt.Sprintf(":%s", port))
	if err != nil {
		panic(err)
	}

	grpcServer := grpc.NewServer()
	grpcAuthServer := api.NewGRPCServer(coreService)
	pb.RegisterAuthServiceServer(grpcServer, grpcAuthServer)

	// give HTTP server time to start up before declaring ready
	go func() {
		time.Sleep(time.Second * 2)
		httpServer.Ready = true
	}()

	err = grpcServer.Serve(lis)
	if err != nil {
		panic(err)
	}
}
