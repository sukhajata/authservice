mockgen -destination=mocks/mockauthclient.go -package=mocks github.com/sukhajata/ppauth AuthServiceClient

mockgen -destination=mocks/mockloggerclient.go -package=mocks github.com/sukhajata/pplogger LoggerServiceClient

mockgen -destination=mocks/mockloggerhelper.go -package=mocks github.com/sukhajata/devicetwin/pkg/loggerhelper Helper

mockgen -destination=mocks/mockkeycloakclient.go -package=mocks github.com/sukhajata/authservice/internal/keycloak Client