package server

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"path"
	"strings"
)

// ChallengeProvider defines the interface for getting HTTP-01 challenge responses
type ChallengeProvider interface {
	GetChallengeResponse(token string) (string, bool)
}

// Server handles HTTP requests for ACME challenges and HTTPS redirects
type Server struct {
	provider ChallengeProvider
	port     int
	server   *http.Server
}

// New creates a new HTTP server
func New(provider ChallengeProvider, port int) *Server {
	return &Server{
		provider: provider,
		port:     port,
	}
}

// Start begins the HTTP server
func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/acme-challenge/", s.handleChallenge)
	mux.HandleFunc("/", s.handleRedirect)

	addr := fmt.Sprintf(":%d", s.port)
	s.server = &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	log.Printf("Starting HTTP server on %s", addr)
	err := s.server.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		if strings.Contains(err.Error(), "permission denied") {
			return fmt.Errorf("failed to start HTTP server: port %d requires root privileges. Try running with sudo", s.port)
		}
		return fmt.Errorf("failed to start HTTP server: %w", err)
	}
	return nil
}

// Stop gracefully stops the HTTP server
func (s *Server) Stop() error {
	if s.server != nil {
		return s.server.Close()
	}
	return nil
}

func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token := path.Base(r.URL.Path)
	if response, ok := s.provider.GetChallengeResponse(token); ok {
		w.Header().Set("Content-Type", "text/plain")
		if _, err := w.Write([]byte(response)); err != nil {
			log.Printf("Error writing challenge response: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		return
	}

	http.NotFound(w, r)
}

func (s *Server) handleRedirect(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	uri := r.RequestURI

	// If the host contains a port, remove it
	if i := strings.IndexByte(host, ':'); i != -1 {
		host = host[:i]
	}

	target := fmt.Sprintf("https://%s%s", host, uri)
	http.Redirect(w, r, target, http.StatusMovedPermanently)
}
