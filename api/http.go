package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/sukhajata/authservice/internal/core"
	"github.com/sukhajata/devicetwin/pkg/loggerhelper"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
	pb "github.com/sukhajata/ppauth"
	"github.com/urfave/negroni"
)

type HTTPServer struct {
	coreService  *core.Service
	loggerHelper loggerhelper.Helper
	Ready        bool
	Live         bool
}

var (
	ready = false
	live  = true
)

func (s *HTTPServer) readinessHandler(w http.ResponseWriter, r *http.Request) {
	if !ready {
		http.Error(w, "Not ready", http.StatusInternalServerError)
		return
	}
	fmt.Fprintf(w, "Ready")
}

func (s *HTTPServer) livenessHandler(w http.ResponseWriter, r *http.Request) {
	if !live {
		http.Error(w, "Not live", http.StatusInternalServerError)
		return
	}
	fmt.Fprintf(w, "Live")
}

func (s *HTTPServer) getTokenHandler(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	var req pb.TokenRequest
	err := decoder.Decode(&req)
	if err != nil {
		fmt.Println("couldn't parse the request")
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	tokenResponse, err := s.coreService.GetToken(&req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	} else if tokenResponse.Token == "" {
		http.Error(w, "failed to get token", http.StatusUnauthorized)
		return
	}

	w.Write([]byte(tokenResponse.Token))

}

// get a token to access the data api
// requires auth header with keycloak token
func (s *HTTPServer) getDataTokenHandler(w http.ResponseWriter, r *http.Request) {
	token, err := extractToken(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	} else if token == "" {
		http.Error(w, "missing token", http.StatusUnauthorized)
		return
	}

	dataToken, err := s.coreService.GetDataAPIToken(token)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	w.Write([]byte(dataToken))

}

func extractToken(r *http.Request) (string, error) {
	var header = r.Header.Get("authorization")
	header = strings.TrimSpace(header)
	if header == "" {
		return "", errors.New("No token")
	}

	splitToken := strings.Split(header, "Bearer ")
	token := splitToken[1]
	return token, nil
}

func NewHTTPServer(coreService *core.Service, loggerHelper loggerhelper.Helper, port string) *HTTPServer {
	s := &HTTPServer{
		coreService:  coreService,
		loggerHelper: loggerHelper,
		Ready:        true,
		Live:         true,
	}
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowCredentials: true,
		AllowedHeaders:   []string{"X-Requested-With", "Content-Type", "Authorization"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE"},
		//Debug: true,
	})

	router := mux.NewRouter()

	router.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "Welcome to the home page!")
	})

	router.HandleFunc("/health/ready", s.readinessHandler).Methods("GET")
	router.HandleFunc("/health/live", s.livenessHandler).Methods("GET")
	router.HandleFunc("/token", s.getTokenHandler).Methods("POST")
	router.HandleFunc("/datatoken", s.getDataTokenHandler).Methods("GET")

	n := negroni.New()
	n.Use(negroni.NewRecovery())
	n.Use(c)

	n.UseHandler(router)

	// start on new goroutine
	go func() {
		n.Run(fmt.Sprintf(":%s", port))
	}()

	return s
}
