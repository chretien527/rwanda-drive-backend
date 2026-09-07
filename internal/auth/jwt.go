package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

type Claims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

type refreshTokenRecord struct {
	ID        string     `bson:"id"`
	UserID    string     `bson:"user_id"`
	TokenHash string     `bson:"token_hash"`
	ExpiresAt time.Time  `bson:"expires_at"`
	UserAgent string     `bson:"user_agent"`
	IPAddress string     `bson:"ip_address"`
	DeviceID  string     `bson:"device_id,omitempty"`
	CreatedAt time.Time  `bson:"created_at"`
	LastUsedAt *time.Time `bson:"last_used_at,omitempty"`
	RevokedAt *time.Time `bson:"revoked_at,omitempty"`
}

const (
	accessTokenTTL  = 15 * time.Minute
	refreshTokenTTL = 7 * 24 * time.Hour
)

func (s *Service) GenerateTokenPair(ctx context.Context, user *User, userAgent, ipAddress string) (*TokenPair, error) {
	now := time.Now()
	accessClaims := &Claims{
		UserID: user.ID,
		Email:  user.Email,
		Role:   user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(accessTokenTTL)),
			IssuedAt:  jwt.NewNumericDate(now),
			Subject:   user.ID,
			Issuer:    "cipherpass",
		},
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessTokenString, err := accessToken.SignedString(s.cfg.Server.JWTSecret)
	if err != nil {
		s.logger.WithError(err).Error("Failed to sign access token")
		return nil, ErrInternal
	}

	refreshToken, err := GenerateRandomHex(32)
	if err != nil {
		s.logger.WithError(err).Error("Failed to generate refresh token")
		return nil, ErrInternal
	}

	_, err = s.db.Collection("refresh_tokens").InsertOne(ctx, refreshTokenRecord{
		ID:        uuid.NewString(),
		UserID:    user.ID,
		TokenHash: hashToken(refreshToken),
		ExpiresAt: now.Add(refreshTokenTTL),
		UserAgent: userAgent,
		IPAddress: ipAddress,
		CreatedAt: now,
	})
	if err != nil {
		s.logger.WithError(err).Error("Failed to store refresh token")
		return nil, ErrInternal
	}

	return &TokenPair{
		AccessToken:  accessTokenString,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(accessTokenTTL.Seconds()),
		TokenType:    "Bearer",
	}, nil
}

func (s *Service) ValidateAccessToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrTokenInvalid
		}
		return s.cfg.Server.JWTSecret, nil
	})
	if err != nil {
		return nil, ErrTokenInvalid
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrTokenInvalid
	}
	return claims, nil
}

func (s *Service) RefreshAccessToken(ctx context.Context, refreshTokenString string, userAgent, ipAddress string) (*TokenPair, error) {
	refreshHash := hashToken(refreshTokenString)

	var record refreshTokenRecord
	err := s.db.Collection("refresh_tokens").FindOne(ctx, bson.M{"token_hash": refreshHash}).Decode(&record)
	if err == mongo.ErrNoDocuments {
		return nil, ErrTokenInvalid
	}
	if err != nil {
		s.logger.WithError(err).Error("Failed to look up refresh token")
		return nil, ErrInternal
	}

	if record.RevokedAt != nil {
		s.logger.WithField("user_id", record.UserID).Warn("Refresh token reuse detected, revoking all sessions")
		_ = s.RevokeAllUserTokens(ctx, record.UserID)
		return nil, ErrTokenRevoked
	}
	if time.Now().After(record.ExpiresAt) {
		return nil, ErrTokenExpired
	}

	now := time.Now()
	_, err = s.db.Collection("refresh_tokens").UpdateOne(ctx, bson.M{"token_hash": refreshHash}, bson.M{"$set": bson.M{"revoked_at": now}})
	if err != nil {
		s.logger.WithError(err).Error("Failed to revoke old refresh token")
	}

	user, err := s.GetUserByID(ctx, record.UserID)
	if err != nil {
		return nil, err
	}
	return s.GenerateTokenPair(ctx, user, userAgent, ipAddress)
}

func (s *Service) RevokeRefreshToken(ctx context.Context, refreshTokenString string) error {
	now := time.Now()
	_, err := s.db.Collection("refresh_tokens").UpdateOne(ctx,
		bson.M{"token_hash": hashToken(refreshTokenString), "revoked_at": bson.M{"$exists": false}},
		bson.M{"$set": bson.M{"revoked_at": now}},
	)
	return err
}

func (s *Service) RevokeAllUserTokens(ctx context.Context, userID string) error {
	now := time.Now()
	_, err := s.db.Collection("refresh_tokens").UpdateMany(ctx,
		bson.M{"user_id": userID, "revoked_at": bson.M{"$exists": false}},
		bson.M{"$set": bson.M{"revoked_at": now}},
	)
	if err != nil {
		s.logger.WithError(err).Error("Failed to revoke all user tokens")
	}
	return err
}

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
