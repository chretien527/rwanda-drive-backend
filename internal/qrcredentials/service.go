package qrcredentials

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"time"

	"github.com/0xEmmyb2/CipherPass/internal/config"
	"github.com/0xEmmyb2/CipherPass/pkg/database"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// QRCredentialService handles rotating token issuance and verification
type QRCredentialService struct {
	db     *database.MongoDB
	logger config.LoggerInterface
	cfg    *config.Config
}

// NewQRCredentialService creates a new QR credential service
func NewQRCredentialService(db *database.MongoDB, logger config.LoggerInterface, cfg *config.Config) *QRCredentialService {
	return &QRCredentialService{
		db:     db,
		logger: logger,
		cfg:    cfg,
	}
}

// Token represents a QR token
type Token struct {
	Value        string    `json:"token"`
	ExpiresAt    time.Time `json:"expires_at"`
	IssuedAt     time.Time `json:"issued_at"`
	CredentialID string    `json:"credential_id,omitempty"` // For verification response only
}

// ActiveToken represents the current active token stored in the database
type ActiveToken struct {
	CredentialID string     `json:"credential_id" bson:"credential_id"`
	Nonce        []byte     `json:"-" bson:"nonce"`
	IssuedAt     time.Time  `json:"issued_at" bson:"issued_at"`
	ConsumedAt   *time.Time `json:"consumed_at,omitempty" bson:"consumed_at,omitempty"`
}

// Error represents an application error
type Error struct {
	Message string `json:"message,omitempty"`
	Code    string `json:"code,omitempty"`
}

func NewError(message, code string) Error {
	return Error{Message: message, Code: code}
}

func (e Error) Error() string {
	return e.Message
}

// Error definitions
var (
	ErrInvalidToken       = NewError("invalid token format", "QR_INVALID_TOKEN")
	ErrInvalidSignature   = NewError("invalid token signature", "QR_INVALID_SIGNATURE")
	ErrTokenExpired       = NewError("token has expired", "QR_TOKEN_EXPIRED")
	ErrTokenNotActive     = NewError("token is no longer active", "QR_TOKEN_NOT_ACTIVE")
	ErrTokenAlreadyUsed   = NewError("token has already been used", "QR_TOKEN_USED")
	ErrCredentialNotFound = NewError("credential not found", "QR_CREDENTIAL_NOT_FOUND")
)

// TokenTTL defines how long a QR token is valid after issuance
const TokenTTL = 40 * time.Second

// RefreshToken issues a new rotating QR token for the given credential (driver).
// It upserts the qr_active_tokens table so only one token is active at a time.
func (s *QRCredentialService) RefreshToken(ctx context.Context, credentialID string) (*Token, error) {
	// Generate 16-byte nonce
	nonce, err := generateRandomBytes(16)
	if err != nil {
		s.logger.WithError(err).Error("Failed to generate nonce")
		return nil, err
	}

	issuedAt := time.Now()

	// Build payload: credentialID || issuedAt(8 bytes BE) || nonce(16 bytes)
	payload := append([]byte(credentialID), append(encodeTime(issuedAt), nonce...)...)

	// HMAC-SHA256(serverSecret, payload)
	signature := computeHMAC(s.cfg.Server.SecretKey, payload)

	// Token = base64url(payload || signature)
	signedPayload := append(payload, signature...)
	token := base64.RawURLEncoding.EncodeToString(signedPayload)

	// UPSERT: replace the existing active token for this credential
	_, err = s.db.Collection("qr_active_tokens").UpdateOne(ctx,
		bson.M{"credential_id": credentialID},
		bson.M{"$set": bson.M{"credential_id": credentialID, "nonce": nonce, "issued_at": issuedAt}, "$unset": bson.M{"consumed_at": ""}},
		options.Update().SetUpsert(true),
	)
	if err != nil {
		s.logger.WithError(err).Error("Failed to upsert QR active token")
		return nil, err
	}

	s.logger.WithField("credential_id", credentialID).Info("QR token refreshed")

	return &Token{
		Value:     token,
		IssuedAt:  issuedAt,
		ExpiresAt: issuedAt.Add(TokenTTL),
	}, nil
}

// VerifyToken validates a QR token against the 5-step check:
// 1. HMAC signature valid
// 2. issuedAt within tolerance window
// 3. Nonce matches the currently active token for that credential
// 4. Token not already consumed
// 5. Credential exists and is active
func (s *QRCredentialService) VerifyToken(ctx context.Context, tokenString string) (*Token, error) {
	// Decode token
	decoded, err := base64.RawURLEncoding.DecodeString(tokenString)
	if err != nil {
		return nil, ErrInvalidToken
	}

	// Extract signature (last 32 bytes for HMAC-SHA256)
	if len(decoded) < 36+8+16+32 { // min: credentialID(36) + timestamp(8) + nonce(16) + signature(32)
		return nil, ErrInvalidToken
	}
	signature := decoded[len(decoded)-32:]
	payload := decoded[:len(decoded)-32]

	// Step 1: Verify HMAC signature
	expectedSignature := computeHMAC(s.cfg.Server.SecretKey, payload)
	if !hmac.Equal(signature, expectedSignature) {
		s.logger.Warn("QR token HMAC verification failed")
		return nil, ErrInvalidSignature
	}

	// Extract credentialID, issuedAt, and nonce from payload
	credentialID := string(payload[:36])
	issuedAtBytes := payload[36 : 36+8]
	nonce := payload[36+8 : 36+8+16]

	issuedAt := decodeTime(issuedAtBytes)

	// Step 2: issuedAt within tolerance window
	now := time.Now()
	if now.After(issuedAt.Add(TokenTTL)) {
		s.logger.WithField("credential_id", credentialID).Warn("QR token expired")
		return nil, ErrTokenExpired
	}
	if now.Before(issuedAt) {
		s.logger.WithField("credential_id", credentialID).Warn("QR token issued_at is in the future")
		return nil, ErrInvalidToken
	}

	// Step 3: Check nonce matches the currently active token
	var active ActiveToken
	err = s.db.Collection("qr_active_tokens").FindOne(ctx, bson.M{"credential_id": credentialID}).Decode(&active)

	if err == mongo.ErrNoDocuments {
		s.logger.WithField("credential_id", credentialID).Warn("No active token for credential")
		return nil, ErrTokenNotActive
	}
	if err != nil {
		s.logger.WithError(err).Error("Failed to query active token")
		return nil, err
	}

	// Step 4: Token not already consumed
	if active.ConsumedAt != nil {
		s.logger.WithField("credential_id", credentialID).Warn("QR token already consumed")
		return nil, ErrTokenAlreadyUsed
	}

	// Nonce comparison
	if len(active.Nonce) != len(nonce) {
		s.logger.WithField("credential_id", credentialID).Warn("QR token nonce length mismatch")
		return nil, ErrTokenNotActive
	}
	for i := range active.Nonce {
		if active.Nonce[i] != nonce[i] {
			s.logger.WithField("credential_id", credentialID).Warn("QR token nonce mismatch")
			return nil, ErrTokenNotActive
		}
	}

	// Step 5: Mark nonce as consumed (first successful scan wins)
	consumedAt := time.Now()
	result, err := s.db.Collection("qr_active_tokens").UpdateOne(ctx,
		bson.M{"credential_id": credentialID, "consumed_at": bson.M{"$exists": false}},
		bson.M{"$set": bson.M{"consumed_at": consumedAt}},
	)
	if err != nil {
		s.logger.WithError(err).Error("Failed to consume QR token")
		return nil, err
	}
	if result.MatchedCount == 0 {
		return nil, ErrTokenAlreadyUsed
	}

	s.logger.WithField("credential_id", credentialID).Info("QR token verified and consumed")

	return &Token{
		Value:        tokenString,
		IssuedAt:     issuedAt,
		ExpiresAt:    issuedAt.Add(TokenTTL),
		CredentialID: credentialID,
	}, nil
}

// IsTokenActive checks if a credential currently has an active (unconsumed) token
func (s *QRCredentialService) IsTokenActive(ctx context.Context, credentialID string) (bool, error) {
	var active ActiveToken
	err := s.db.Collection("qr_active_tokens").FindOne(ctx, bson.M{"credential_id": credentialID}).Decode(&active)

	if err == mongo.ErrNoDocuments {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return active.ConsumedAt == nil, nil
}

// --- Helper functions ---

func computeHMAC(key []byte, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// encodeTime converts time.Time to 8-byte big-endian Unix timestamp
func encodeTime(t time.Time) []byte {
	ts := uint64(t.Unix())
	b := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		b[i] = byte(ts & 0xff)
		ts >>= 8
	}
	return b
}

// decodeTime converts 8-byte big-endian Unix timestamp back to time.Time
func decodeTime(b []byte) time.Time {
	var ts uint64
	for i := 0; i < 8; i++ {
		ts = (ts << 8) | uint64(b[i])
	}
	return time.Unix(int64(ts), 0)
}

// generateRandomBytes returns securely random bytes
func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}
