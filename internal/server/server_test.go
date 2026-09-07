package server

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/0xEmmyb2/CipherPass/internal/config"
	"github.com/stretchr/testify/require"
)

// TestHealthCheck verifies the health check endpoint returns OK
func TestHealthCheck(t *testing.T) {
	// Create test configuration
	cfg := &config.Config{
		Environment: config.Development,
		Server: config.ServerConfig{
			Address:        ":0", // Let OS assign a free port
			ReadTimeout:    5 * time.Second,
			WriteTimeout:   5 * time.Second,
			IdleTimeout:    10 * time.Second,
			MaxHeaderBytes: 1 << 20,
			SecretKey:      []byte("test-qr-secret"),
			JWTSecret:      []byte("test-jwt-secret"),
		},
		Database: config.DatabaseConfig{
			URI:  "mongodb://localhost:27017",
			Name: "cipherpass_test",
		},
		LogLevel: "debug",
	}

	// Create logger
	logger := config.NewLogger(cfg.Environment)

	// Create server
	srv, err := NewServer(cfg, logger)
	require.NoError(t, err)

	// Get the actual address the server is listening on
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	// Start server in a goroutine
	go func() {
		if err := srv.httpServer.Serve(listener); err != nil && err != http.ErrServerClosed {
			t.Errorf("Server error: %v", err)
		}
	}()

	// Give server a moment to start
	time.Sleep(100 * time.Millisecond)

	// Make HTTP request to health check endpoint
	resp, err := http.Get("http://" + listener.Addr().String() + "/healthz")
	require.NoError(t, err)
	defer resp.Body.Close()

	// Check response
	require.Equal(t, http.StatusOK, resp.StatusCode, "Expected OK status")

	// Stop the server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Stop(ctx); err != nil {
		t.Fatalf("Failed to stop server: %v", err)
	}
}
