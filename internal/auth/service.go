package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/0xEmmyb2/CipherPass/internal/config"
	"github.com/0xEmmyb2/CipherPass/pkg/database"
	"golang.org/x/crypto/bcrypt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// Role constants
const (
	RoleDriver     = "DRIVER"
	RoleOfficer    = "OFFICER"
	RoleAdmin      = "ADMIN"
	RoleSuperAdmin = "SUPER_ADMIN"
)

// Password hashing cost — 12 is a good balance of security and speed for a server
const bcryptCost = 12

// Service handles authentication-related business logic
type Service struct {
	db           *database.MongoDB
	logger       config.LoggerInterface
	cfg          *config.Config
	emailService *EmailService
}

// NewService creates a new authentication service
func NewService(db *database.MongoDB, logger config.LoggerInterface, cfg *config.Config) *Service {
	return &Service{
		db:           db,
		logger:       logger,
		cfg:          cfg,
		emailService: NewEmailService(logger.(*config.Logger)),
	}
}

// User represents a user in the system
type User struct {
	ID                  string     `json:"id" bson:"id"`
	FullName            string     `json:"full_name,omitempty" bson:"full_name,omitempty"`
	Email               string     `json:"email" bson:"email"`
	Phone               *string    `json:"phone,omitempty" bson:"phone,omitempty"`
	PasswordHash        string     `json:"-" bson:"password_hash"`
	Role                string     `json:"role" bson:"role"`
	EmailVerified       bool       `json:"email_verified" bson:"email_verified"`
	DocumentVerified    bool       `json:"document_verified" bson:"document_verified"`
	BiometricVerified   bool       `json:"biometric_verified" bson:"biometric_verified"`
	MFAEnabled          bool       `json:"mfa_enabled" bson:"mfa_enabled"`
	MFASecret           *string    `json:"-" bson:"mfa_secret,omitempty"`
	CreatedAt           time.Time  `json:"created_at" bson:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at" bson:"updated_at"`
	LastLoginAt         *time.Time `json:"last_login_at,omitempty" bson:"last_login_at,omitempty"`
	IsActive            bool       `json:"is_active" bson:"is_active"`
	FailedLoginAttempts int        `json:"-" bson:"failed_login_attempts"`
	LockedUntil         *time.Time `json:"-" bson:"locked_until,omitempty"`
}

// CreateUser registers a new user with the given role
func (s *Service) CreateUser(ctx context.Context, fullName, email, phone, password, role string) (*User, error) {
	hash, err := HashPassword(password)
	if err != nil {
		s.logger.WithError(err).Error("Failed to hash password")
		return nil, ErrInternal
	}

	now := time.Now()
	var phonePtr *string
	if phone != "" {
		phonePtr = &phone
	}
	user := &User{
		ID:                uuid.NewString(),
		FullName:          fullName,
		Email:             email,
		Phone:             phonePtr,
		PasswordHash:      hash,
		Role:              role,
		EmailVerified:     role != RoleDriver,
		DocumentVerified:  false,
		BiometricVerified: false,
		MFAEnabled:        false,
		CreatedAt:         now,
		UpdatedAt:         now,
		IsActive:          true,
	}

	_, err = s.db.Collection("users").InsertOne(ctx, user)
	if err != nil {
		s.logger.WithError(err).Error("Failed to create user")
		return nil, ErrInternal
	}

	s.logger.WithField("user_id", user.ID).Info("User created")
	return user, nil
}

// GetUserByEmail looks up a user by email
func (s *Service) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	var user User
	err := s.db.Collection("users").FindOne(ctx, bson.M{"email": email}).Decode(&user)
	if err == mongo.ErrNoDocuments {
		return nil, ErrUserNotFound
	}
	if err != nil {
		s.logger.WithError(err).Error("Failed to fetch user by email")
		return nil, ErrInternal
	}

	return &user, nil
}

// GetUserByID looks up a user by ID
func (s *Service) GetUserByID(ctx context.Context, id string) (*User, error) {
	var user User
	err := s.db.Collection("users").FindOne(ctx, bson.M{"id": id}).Decode(&user)
	if err == mongo.ErrNoDocuments {
		return nil, ErrUserNotFound
	}
	if err != nil {
		s.logger.WithError(err).Error("Failed to fetch user by ID")
		return nil, ErrInternal
	}

	return &user, nil
}

// Authenticate verifies email+password and returns the user if valid.
// Gates: is_active, locked_until, email_verified checks.
func (s *Service) Authenticate(ctx context.Context, email, password string) (*User, error) {
	user, err := s.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, err
	}

	if !user.IsActive {
		return nil, ErrAccountDisabled
	}

	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		return nil, ErrAccountLocked
	}

	// Email verification gate — unverified drivers cannot log in.
	// Officers/Admins are created via invite (email is verified at invite creation time).
	if user.Role == RoleDriver && !user.EmailVerified {
		return nil, ErrEmailNotVerified
	}

	if !CheckPasswordHash(user.PasswordHash, password) {
		// Increment failed attempts
		s.incrementFailedLoginAttempts(ctx, user)
		return nil, ErrInvalidCredentials
	}

	// Reset failed attempts and update last login
	now := time.Now()
	_, err = s.db.Collection("users").UpdateOne(ctx, bson.M{"id": user.ID}, bson.M{
		"$set":   bson.M{"failed_login_attempts": 0, "last_login_at": now, "updated_at": now},
		"$unset": bson.M{"locked_until": ""},
	})
	if err != nil {
		s.logger.WithError(err).Error("Failed to update login info")
	}

	// Reload user with updated fields
	return s.GetUserByID(ctx, user.ID)
}

// incrementFailedLoginAttempts locks the account after 5 consecutive failures
func (s *Service) incrementFailedLoginAttempts(ctx context.Context, user *User) {
	const maxAttempts = 5
	newAttempts := user.FailedLoginAttempts + 1

	if newAttempts >= maxAttempts {
		lockDuration := 15 * time.Minute
		lockUntil := time.Now().Add(lockDuration)
		_, err := s.db.Collection("users").UpdateOne(ctx, bson.M{"id": user.ID}, bson.M{
			"$set": bson.M{"failed_login_attempts": newAttempts, "locked_until": lockUntil, "updated_at": time.Now()},
		})
		if err != nil {
			s.logger.WithError(err).Error("Failed to lock account")
		}
		s.logger.WithField("user_id", user.ID).Warn("Account locked due to too many failed login attempts")
	} else {
		_, err := s.db.Collection("users").UpdateOne(ctx, bson.M{"id": user.ID}, bson.M{
			"$set": bson.M{"failed_login_attempts": newAttempts, "updated_at": time.Now()},
		})
		if err != nil {
			s.logger.WithError(err).Error("Failed to increment failed login attempts")
		}
	}
}

// --- Password helpers ---

// HashPassword hashes a password using bcrypt
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// CheckPasswordHash compares a bcrypt hash with a plaintext password
func CheckPasswordHash(hash, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// --- Random token helpers ---

// GenerateRandomBytes returns securely random bytes
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// GenerateRandomHex returns a securely random hex string
func GenerateRandomHex(n int) (string, error) {
	bytes, err := GenerateRandomBytes(n)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// GenerateOTP generates a 6-digit numeric OTP
func GenerateOTP() (string, error) {
	// Generate 3 random bytes (24 bits) 
	bytes, err := GenerateRandomBytes(3)
	if err != nil {
		return "", err
	}
	
	// Convert to number and ensure it's 6 digits
	num := int(bytes[0])<<16 | int(bytes[1])<<8 | int(bytes[2])
	// Ensure 6 digits (100000 to 999999)
	otp := (num % 900000) + 100000
	
	return fmt.Sprintf("%06d", otp), nil
}

// ════════════════════════════════════════════════
// MFA Login Token (short-lived JWT for the MFA step)
// ════════════════════════════════════════════════

// MFALoginClaims is a special JWT used only during the MFA login flow.
type MFALoginClaims struct {
	UserID string `json:"user_id"`
	jwt.RegisteredClaims
}

// GenerateMFALoginToken creates a short-lived (5 min) JWT for the MFA verification step.
func (s *Service) GenerateMFALoginToken(ctx context.Context, userID string) (string, error) {
	claims := &MFALoginClaims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   userID,
			Issuer:    "cipherpass-mfa",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(s.cfg.Server.JWTSecret)
	if err != nil {
		s.logger.WithError(err).Error("Failed to sign MFA login token")
		return "", ErrInternal
	}

	return tokenString, nil
}

// ValidateMFALoginToken parses and validates an MFA login token, returning the user ID.
func (s *Service) ValidateMFALoginToken(tokenString string) (string, error) {
	token, err := jwt.ParseWithClaims(tokenString, &MFALoginClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrTokenInvalid
		}
		return s.cfg.Server.JWTSecret, nil
	})

	if err != nil {
		return "", ErrTokenInvalid
	}

	claims, ok := token.Claims.(*MFALoginClaims)
	if !ok || !token.Valid {
		return "", ErrTokenInvalid
	}

	return claims.UserID, nil
}

// MarkEmailVerified directly marks a user's email as verified (used for invite-based provisioning)
func (s *Service) MarkEmailVerified(ctx context.Context, userID string) error {
	_, err := s.db.Collection("users").UpdateOne(ctx, bson.M{"id": userID}, bson.M{"$set": bson.M{"email_verified": true, "updated_at": time.Now()}})
	return err
}
