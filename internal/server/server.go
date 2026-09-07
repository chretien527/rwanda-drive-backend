package server

import (
	"context"
	"net/http"
	"time"

	"github.com/0xEmmyb2/CipherPass/internal/config"
	"github.com/gorilla/mux"
)

// Server holds the HTTP server configuration
type Server struct {
	httpServer *http.Server
	Router     *mux.Router
	Logger     *config.Logger
	Config     *config.Config
}

// NewServer creates a new HTTP server with middleware
func NewServer(cfg *config.Config, logger *config.Logger) (*Server, error) {
	// Create router
	router := mux.NewRouter()

	// Create server instance
	s := &Server{
		Router: router,
		Logger: logger,
		Config: cfg,
	}

	// Setup middleware chain
	s.setupMiddleware()

	// Setup routes
	s.setupRoutes()

	// Create HTTP server
	s.httpServer = &http.Server{
		Addr:              cfg.Server.Address,
		Handler:           s.Router,
		ReadHeaderTimeout: cfg.Server.ReadTimeout,
		ReadTimeout:       cfg.Server.ReadTimeout,
		WriteTimeout:      cfg.Server.WriteTimeout,
		IdleTimeout:       cfg.Server.IdleTimeout,
		MaxHeaderBytes:    cfg.Server.MaxHeaderBytes,
	}

	return s, nil
}

// setupMiddleware applies the middleware chain
func (s *Server) setupMiddleware() {
	// Apply middleware in order: CORS first (before routing) → Request ID → Logging → Recovery → Security Headers
	// CORS must be first to handle OPTIONS preflight requests before the router rejects them
	s.Router.Use(corsMiddleware)
	s.Router.Use(requestIDMiddleware)
	s.Router.Use(loggingMiddleware(s.Logger))
	s.Router.Use(recoveryMiddleware(s.Logger))
	s.Router.Use(securityHeadersMiddleware)
}

// setupRoutes defines the API routes
func (s *Server) setupRoutes() {
	// Health check endpoint (no auth required)
	s.Router.HandleFunc("/healthz", s.healthCheckHandler).Methods("GET")

	// Global OPTIONS handler for CORS preflight requests
	// This catches all OPTIONS requests before specific route handlers
	s.Router.Methods("OPTIONS").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// CORS middleware already set headers, just return 204
		w.WriteHeader(http.StatusNoContent)
	})

	// All API routes are under /api/v1
	// Auth and QR routes are registered by their respective handlers
	// via RegisterRoutes(s.Router) in main.go
}

// healthCheckHandler returns a simple health check
func (s *Server) healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok","timestamp":"` + time.Now().UTC().Format(time.RFC3339) + `"}`))
}

// Start begins listening and serving HTTP requests
func (s *Server) Start() error {
	s.Logger.Infof("Server starting on %s", s.Config.Server.Address)
	return s.httpServer.ListenAndServe()
}

// Stop gracefully shuts down the server
func (s *Server) Stop(ctx context.Context) error {
	s.Logger.Info("Shutting down server...")
	return s.httpServer.Shutdown(ctx)
}
