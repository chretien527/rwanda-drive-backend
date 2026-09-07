package auth

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	otpLength       = 6
	otpTTL          = 5 * time.Minute
	otpMaxAttempts  = 3
	otpResendWindow = 15 * time.Minute
	otpResendLimit  = 3
)

type PhoneOTP struct {
	ID         string     `json:"id" bson:"id"`
	UserID     string     `json:"user_id" bson:"user_id"`
	Code       string     `json:"-" bson:"code"`
	Purpose    string     `json:"purpose" bson:"purpose"`
	ExpiresAt  time.Time  `json:"expires_at" bson:"expires_at"`
	VerifiedAt *time.Time `json:"verified_at,omitempty" bson:"verified_at,omitempty"`
	Attempts   int        `json:"attempts" bson:"attempts"`
	CreatedAt  time.Time  `json:"created_at" bson:"created_at"`
}

func (s *Service) GeneratePhoneOTP(ctx context.Context, userID, purpose string) (string, error) {
	_, err := s.db.Collection("phone_otps").DeleteMany(ctx, bson.M{
		"user_id": userID, "purpose": purpose, "verified_at": bson.M{"$exists": false},
	})
	if err != nil {
		s.logger.WithError(err).Error("Failed to invalidate old OTPs")
	}

	code, err := generateOTPCode()
	if err != nil {
		s.logger.WithError(err).Error("Failed to generate OTP code")
		return "", ErrInternal
	}

	now := time.Now()
	_, err = s.db.Collection("phone_otps").InsertOne(ctx, PhoneOTP{
		ID:        uuid.NewString(),
		UserID:    userID,
		Code:      code,
		Purpose:   purpose,
		ExpiresAt: now.Add(otpTTL),
		CreatedAt: now,
	})
	if err != nil {
		s.logger.WithError(err).Error("Failed to store OTP")
		return "", ErrInternal
	}

	s.logger.WithFields(map[string]interface{}{"user_id": userID, "purpose": purpose}).Info("Phone OTP generated")
	return code, nil
}

func (s *Service) VerifyPhoneOTP(ctx context.Context, userID, code, purpose string) error {
	var otp PhoneOTP
	err := s.db.Collection("phone_otps").FindOne(ctx,
		bson.M{"user_id": userID, "purpose": purpose},
		options.FindOne().SetSort(bson.D{{Key: "created_at", Value: -1}}),
	).Decode(&otp)
	if err == mongo.ErrNoDocuments {
		return ErrOTPNotFound
	}
	if err != nil {
		s.logger.WithError(err).Error("Failed to look up OTP")
		return ErrInternal
	}
	if otp.VerifiedAt != nil {
		return ErrOTPAlreadyVerified
	}
	if time.Now().After(otp.ExpiresAt) {
		return ErrOTPExpired
	}
	if otp.Attempts >= otpMaxAttempts {
		return ErrOTPMaxAttempts
	}

	_, err = s.db.Collection("phone_otps").UpdateOne(ctx, bson.M{"id": otp.ID}, bson.M{"$inc": bson.M{"attempts": 1}})
	if err != nil {
		s.logger.WithError(err).Error("Failed to increment OTP attempts")
	}
	if otp.Code != code {
		return ErrOTPInvalid
	}

	now := time.Now()
	_, err = s.db.Collection("phone_otps").UpdateOne(ctx, bson.M{"id": otp.ID}, bson.M{"$set": bson.M{"verified_at": now}})
	if err != nil {
		s.logger.WithError(err).Error("Failed to mark OTP as verified")
		return ErrInternal
	}

	s.logger.WithFields(map[string]interface{}{"user_id": userID, "purpose": purpose}).Info("Phone OTP verified")
	return nil
}

func (s *Service) CheckPhoneOTPRateLimit(ctx context.Context, userID, purpose string) error {
	count, err := s.db.Collection("phone_otps").CountDocuments(ctx, bson.M{
		"user_id": userID, "purpose": purpose, "created_at": bson.M{"$gt": time.Now().Add(-otpResendWindow)},
	})
	if err != nil {
		s.logger.WithError(err).Error("Failed to count recent OTPs")
		return ErrInternal
	}
	if count >= otpResendLimit {
		return ErrRateLimited
	}
	return nil
}

func generateOTPCode() (string, error) {
	max := big.NewInt(999999)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%0*d", otpLength, n.Int64()), nil
}
