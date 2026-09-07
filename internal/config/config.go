package config

import (
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/joho/godotenv"
)

// Environment represents the deployment environment
type Environment string

const (
	Development Environment = "development"
	Staging     Environment = "staging"
	Production  Environment = "production"
)

// Config holds all application configuration
type Config struct {
	Environment Environment
	Server      ServerConfig
	Database    DatabaseConfig
	Chain       ChainConfig
	LogLevel    string
}

// ServerConfig holds HTTP server configuration
type ServerConfig struct {
	Address        string
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	IdleTimeout    time.Duration
	MaxHeaderBytes int
	SecretKey      []byte // HMAC signing key for QR tokens
	JWTSecret      []byte // Secret for signing JWT access/refresh tokens
}

// DatabaseConfig holds MongoDB connection configuration
type DatabaseConfig struct {
	URI  string
	Name string
}

// ChainConfig holds blockchain integration configuration
type ChainConfig struct {
	RPCURL             string         // Ethereum RPC endpoint (e.g., Infura, Alchemy, or local node)
	ChainID            *big.Int       // Chain ID for EIP-155 transaction signing
	LicenseRegistry    common.Address // Address of LicenseRegistry.sol
	CredentialRegistry common.Address // Address of CredentialRegistry.sol
	AuditAnchor        common.Address // Address of AuditAnchor.sol
	KMS                KMSConfig      // KMS signer configuration
	BlockConfirmations uint64         // Number of block confirmations before processing an event
	PollInterval       time.Duration  // How often to poll for new events
}

// KMSConfig holds KMS signer configuration
type KMSConfig struct {
	Provider string // "aws", "gcp", or "local" (for development)
	KeyID    string // KMS key ID or ARN
	Region   string // AWS/GCP region
	LocalKey string // Hex-encoded private key for local dev signing (NEVER use in production)
}

// Load loads configuration from environment variables and .env file
func Load() (*Config, error) {
	_ = godotenv.Load()

	secretKey := getEnv("QR_SECRET_KEY", "dev-qr-secret-change-me-in-production")
	jwtSecret := getEnv("JWT_SECRET", "dev-jwt-secret-change-me-in-production")

	chainID := new(big.Int)
	chainID.SetString(getEnv("CHAIN_ID", "31337"), 10) // Default to Anvil local chain

	cfg := &Config{
		Environment: Environment(getEnv("ENVIRONMENT", string(Development))),
		Server: ServerConfig{
			Address:        getEnv("SERVER_ADDRESS", ":8080"),
			ReadTimeout:    mustParseDuration(getEnv("SERVER_READ_TIMEOUT", "15s")),
			WriteTimeout:   mustParseDuration(getEnv("SERVER_WRITE_TIMEOUT", "15s")),
			IdleTimeout:    mustParseDuration(getEnv("SERVER_IDLE_TIMEOUT", "60s")),
			MaxHeaderBytes: mustParseInt(getEnv("SERVER_MAX_HEADER_BYTES", "1048576")),
			SecretKey:      []byte(secretKey),
			JWTSecret:      []byte(jwtSecret),
		},
		Database: DatabaseConfig{
			URI:  getEnv("MONGODB_URI", "mongodb://localhost:27017"),
			Name: getEnv("MONGODB_DATABASE", "rwanda_drive"),
		},
		Chain: ChainConfig{
			RPCURL:             getEnv("CHAIN_RPC_URL", "http://127.0.0.1:8545"),
			ChainID:            chainID,
			LicenseRegistry:    common.HexToAddress(getEnv("LICENSE_REGISTRY_ADDR", "0x0000000000000000000000000000000000000000")),
			CredentialRegistry: common.HexToAddress(getEnv("CREDENTIAL_REGISTRY_ADDR", "0x0000000000000000000000000000000000000000")),
			AuditAnchor:        common.HexToAddress(getEnv("AUDIT_ANCHOR_ADDR", "0x0000000000000000000000000000000000000000")),
			KMS: KMSConfig{
				Provider: getEnv("KMS_PROVIDER", "local"),
				KeyID:    getEnv("KMS_KEY_ID", ""),
				Region:   getEnv("KMS_REGION", ""),
				LocalKey: getEnv("KMS_LOCAL_KEY", "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"),
			},
			BlockConfirmations: uint64(mustParseInt(getEnv("BLOCK_CONFIRMATIONS", "1"))),
			PollInterval:       mustParseDuration(getEnv("CHAIN_POLL_INTERVAL", "2s")),
		},
		LogLevel: getEnv("LOG_LEVEL", "info"),
	}

	return cfg, nil
}

// NewLogger creates a structured logger appropriate for the environment
func NewLogger(env Environment) *Logger {
	return NewJSONLogger(env == Development)
}

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

func mustParseDuration(s string) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		panic("failed to parse duration " + s + ": " + err.Error())
	}
	return d
}

func mustParseInt(s string) int {
	var i int
	_, err := fmt.Sscanf(s, "%d", &i)
	if err != nil {
		panic("failed to parse int " + s + ": " + err.Error())
	}
	return i
}
