package config

import (
	"os"
	"testing"
	"time"

	"github.com/joho/godotenv"
	"github.com/stretchr/testify/require"
)

// TestLoadDefaultConfig verifies that config loads with default values when no env vars are set
func TestLoadDefaultConfig(t *testing.T) {
	// Clear relevant environment variables
	cleanEnv := []string{
		"ENVIRONMENT", "SERVER_ADDRESS", "SERVER_READ_TIMEOUT", "SERVER_WRITE_TIMEOUT",
		"SERVER_IDLE_TIMEOUT", "SERVER_MAX_HEADER_BYTES", "MONGODB_URI", "MONGODB_DATABASE", "LOG_LEVEL",
		"QR_SECRET_KEY", "JWT_SECRET", "CHAIN_RPC_URL", "CHAIN_ID",
		"LICENSE_REGISTRY_ADDR", "CREDENTIAL_REGISTRY_ADDR", "AUDIT_ANCHOR_ADDR",
		"KMS_PROVIDER", "KMS_KEY_ID", "KMS_REGION",
	}
	for _, key := range cleanEnv {
		os.Unsetenv(key)
	}

	_ = godotenv.Unset()

	cfg, err := Load()
	require.NoError(t, err)

	// Check server defaults
	require.Equal(t, Development, cfg.Environment)
	require.Equal(t, ":8080", cfg.Server.Address)
	require.Equal(t, time.Second*15, cfg.Server.ReadTimeout)
	require.Equal(t, time.Second*15, cfg.Server.WriteTimeout)
	require.Equal(t, time.Second*60, cfg.Server.IdleTimeout)
	require.Equal(t, 1048576, cfg.Server.MaxHeaderBytes)

	// Check database defaults
	require.Equal(t, "mongodb://localhost:27017", cfg.Database.URI)
	require.Equal(t, "rwanda_drive", cfg.Database.Name)

	// Check chain defaults
	require.NotNil(t, cfg.Chain.ChainID)
	require.Equal(t, "http://127.0.0.1:8545", cfg.Chain.RPCURL)
	require.Equal(t, "local", cfg.Chain.KMS.Provider)
	require.Equal(t, uint64(1), cfg.Chain.BlockConfirmations)

	require.Equal(t, "info", cfg.LogLevel)
}

// TestLoadCustomConfig verifies that config loads custom values from environment variables
func TestLoadCustomConfig(t *testing.T) {
	os.Setenv("ENVIRONMENT", "production")
	os.Setenv("SERVER_ADDRESS", ":9090")
	os.Setenv("SERVER_READ_TIMEOUT", "30s")
	os.Setenv("SERVER_WRITE_TIMEOUT", "30s")
	os.Setenv("SERVER_IDLE_TIMEOUT", "120s")
	os.Setenv("SERVER_MAX_HEADER_BYTES", "2097152")
	os.Setenv("MONGODB_URI", "mongodb://db.example.com:27017")
	os.Setenv("MONGODB_DATABASE", "production_db")
	os.Setenv("LOG_LEVEL", "error")
	os.Setenv("CHAIN_RPC_URL", "https://mainnet.infura.io/v3/abc123")
	os.Setenv("CHAIN_ID", "1")
	os.Setenv("KMS_PROVIDER", "aws")
	os.Setenv("KMS_KEY_ID", "arn:aws:kms:us-east-1:123456789:key/abc-123")

	cfg, err := Load()
	require.NoError(t, err)

	require.Equal(t, Production, cfg.Environment)
	require.Equal(t, ":9090", cfg.Server.Address)
	require.Equal(t, time.Second*30, cfg.Server.ReadTimeout)
	require.Equal(t, time.Second*30, cfg.Server.WriteTimeout)
	require.Equal(t, time.Second*120, cfg.Server.IdleTimeout)
	require.Equal(t, 2097152, cfg.Server.MaxHeaderBytes)
	require.Equal(t, "mongodb://db.example.com:27017", cfg.Database.URI)
	require.Equal(t, "production_db", cfg.Database.Name)
	require.Equal(t, "error", cfg.LogLevel)

	// Check chain config
	require.Equal(t, "https://mainnet.infura.io/v3/abc123", cfg.Chain.RPCURL)
	require.Equal(t, "aws", cfg.Chain.KMS.Provider)
	require.Equal(t, "arn:aws:kms:us-east-1:123456789:key/abc-123", cfg.Chain.KMS.KeyID)
}
