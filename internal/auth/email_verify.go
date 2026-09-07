package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type EmailVerification struct {
	ID         string     `json:"id" bson:"id"`
	UserID     string     `json:"user_id" bson:"user_id"`
	TokenHash  string     `json:"-" bson:"token_hash"`
	ExpiresAt  time.Time  `json:"expires_at" bson:"expires_at"`
	VerifiedAt *time.Time `json:"verified_at,omitempty" bson:"verified_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at" bson:"created_at"`
}

func (s *Service) GenerateEmailVerification(ctx context.Context, userID string) (string, error) {
	// Get user for email address
	user, err := s.GetUserByID(ctx, userID)
	if err != nil {
		s.logger.WithError(err).Error("Failed to fetch user for email verification")
		return "", ErrInternal
	}

	// Invalidate old tokens
	_, err = s.db.Collection("email_verifications").DeleteMany(ctx, bson.M{
		"user_id": userID, "verified_at": bson.M{"$exists": false},
	})
	if err != nil {
		s.logger.WithError(err).Error("Failed to invalidate old email verification tokens")
	}

	// Generate 6-digit OTP
	otp, err := GenerateOTP()
	if err != nil {
		s.logger.WithError(err).Error("Failed to generate email verification OTP")
		return "", ErrInternal
	}

	now := time.Now()
	_, err = s.db.Collection("email_verifications").InsertOne(ctx, EmailVerification{
		ID:        uuid.NewString(),
		UserID:    userID,
		TokenHash: emailVerifyTokenHash(otp),
		ExpiresAt: now.Add(24 * time.Hour),
		CreatedAt: now,
	})
	if err != nil {
		s.logger.WithError(err).Error("Failed to store email verification OTP")
		return "", ErrInternal
	}

	// Send verification email with OTP
	err = s.emailService.SendVerificationOTP(user.Email, otp)
	if err != nil {
		s.logger.WithError(err).Error("Failed to send verification email")
		// Don't return error - OTP is still valid even if email fails
	}

	s.logger.WithField("user_id", userID).Info("Email verification OTP generated and sent")
	return otp, nil
}

func (s *Service) VerifyEmail(ctx context.Context, token string) error {
	var verification EmailVerification
	err := s.db.Collection("email_verifications").FindOne(ctx, bson.M{"token_hash": emailVerifyTokenHash(token)}).Decode(&verification)
	if err == mongo.ErrNoDocuments {
		return ErrEmailVerificationNotFound
	}
	if err != nil {
		s.logger.WithError(err).Error("Failed to look up email verification token")
		return ErrInternal
	}
	if verification.VerifiedAt != nil {
		return ErrEmailAlreadyVerified
	}
	if time.Now().After(verification.ExpiresAt) {
		return ErrEmailVerificationExpired
	}

	now := time.Now()
	_, err = s.db.Collection("email_verifications").UpdateOne(ctx, bson.M{"id": verification.ID}, bson.M{"$set": bson.M{"verified_at": now}})
	if err != nil {
		s.logger.WithError(err).Error("Failed to mark email verification as verified")
		return ErrInternal
	}
	_, err = s.db.Collection("users").UpdateOne(ctx, bson.M{"id": verification.UserID}, bson.M{"$set": bson.M{"email_verified": true, "updated_at": now}})
	if err != nil {
		s.logger.WithError(err).Error("Failed to update user email_verified status")
		return ErrInternal
	}

	s.logger.WithField("user_id", verification.UserID).Info("Email verified successfully")
	return nil
}

func (s *Service) ResendEmailVerification(ctx context.Context, userID string) (string, error) {
	count, err := s.db.Collection("email_verifications").CountDocuments(ctx, bson.M{
		"user_id": userID, "created_at": bson.M{"$gt": time.Now().Add(-1 * time.Hour)},
	})
	if err != nil {
		s.logger.WithError(err).Error("Failed to count recent email verification tokens")
		return "", ErrInternal
	}
	if count >= 3 {
		return "", ErrRateLimited
	}
	return s.GenerateEmailVerification(ctx, userID)
}

// ResendEmailVerificationByEmail resends a verification OTP for an unverified account.
// Returns nil when the email is unknown or already verified to avoid leaking account state.
func (s *Service) ResendEmailVerificationByEmail(ctx context.Context, email string) error {
	user, err := s.GetUserByEmail(ctx, email)
	if err != nil {
		return nil
	}
	if user.EmailVerified {
		return nil
	}
	_, err = s.ResendEmailVerification(ctx, user.ID)
	return err
}

func emailVerifyTokenHash(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
