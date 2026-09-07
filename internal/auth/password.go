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

type PasswordReset struct {
	ID        string     `json:"id" bson:"id"`
	UserID    string     `json:"user_id" bson:"user_id"`
	TokenHash string     `json:"-" bson:"token_hash"`
	ExpiresAt time.Time  `json:"expires_at" bson:"expires_at"`
	UsedAt    *time.Time `json:"used_at,omitempty" bson:"used_at,omitempty"`
	CreatedAt time.Time  `json:"created_at" bson:"created_at"`
}

func (s *Service) ChangePassword(ctx context.Context, userID, currentPassword, newPassword string) error {
	user, err := s.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if !CheckPasswordHash(user.PasswordHash, currentPassword) {
		return ErrInvalidCredentials
	}

	hash, err := HashPassword(newPassword)
	if err != nil {
		s.logger.WithError(err).Error("Failed to hash new password")
		return ErrInternal
	}

	_, err = s.db.Collection("users").UpdateOne(ctx,
		bson.M{"id": userID},
		bson.M{"$set": bson.M{"password_hash": hash, "updated_at": time.Now()}},
	)
	if err != nil {
		s.logger.WithError(err).Error("Failed to update password")
		return ErrInternal
	}

	if err := s.RevokeAllUserTokens(ctx, userID); err != nil {
		s.logger.WithError(err).Error("Failed to revoke sessions after password change")
	}
	s.logger.WithField("user_id", userID).Info("Password changed")
	return nil
}

func (s *Service) ForgotPassword(ctx context.Context, email string) (string, error) {
	user, err := s.GetUserByEmail(ctx, email)
	if err != nil {
		// Don't reveal if user exists or not for security
		return "", nil
	}

	_, err = s.db.Collection("password_resets").DeleteMany(ctx, bson.M{
		"user_id": user.ID, "used_at": bson.M{"$exists": false},
	})
	if err != nil {
		s.logger.WithError(err).Error("Failed to invalidate old password reset tokens")
	}

	// Generate 6-digit OTP instead of long token
	otp, err := GenerateOTP()
	if err != nil {
		s.logger.WithError(err).Error("Failed to generate password reset OTP")
		return "", ErrInternal
	}

	now := time.Now()
	_, err = s.db.Collection("password_resets").InsertOne(ctx, PasswordReset{
		ID:        uuid.NewString(),
		UserID:    user.ID,
		TokenHash: passwordResetTokenHash(otp),
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
	})
	if err != nil {
		s.logger.WithError(err).Error("Failed to store password reset OTP")
		return "", ErrInternal
	}

	// Send password reset email with OTP
	err = s.emailService.SendPasswordResetOTP(user.Email, otp)
	if err != nil {
		s.logger.WithError(err).Error("Failed to send password reset email")
		// Don't return error - OTP is still valid even if email fails
	}

	s.logger.WithField("user_id", user.ID).Info("Password reset OTP generated and sent")
	return otp, nil
}

func (s *Service) ResetPassword(ctx context.Context, token, newPassword string) error {
	var reset PasswordReset
	err := s.db.Collection("password_resets").FindOne(ctx, bson.M{"token_hash": passwordResetTokenHash(token)}).Decode(&reset)
	if err == mongo.ErrNoDocuments {
		return ErrPasswordResetNotFound
	}
	if err != nil {
		s.logger.WithError(err).Error("Failed to look up password reset token")
		return ErrInternal
	}
	if reset.UsedAt != nil {
		return ErrPasswordResetUsed
	}
	if time.Now().After(reset.ExpiresAt) {
		return ErrPasswordResetExpired
	}

	hash, err := HashPassword(newPassword)
	if err != nil {
		s.logger.WithError(err).Error("Failed to hash new password")
		return ErrInternal
	}

	now := time.Now()
	_, err = s.db.Collection("password_resets").UpdateOne(ctx, bson.M{"id": reset.ID}, bson.M{"$set": bson.M{"used_at": now}})
	if err != nil {
		s.logger.WithError(err).Error("Failed to mark password reset as used")
		return ErrInternal
	}
	_, err = s.db.Collection("users").UpdateOne(ctx,
		bson.M{"id": reset.UserID},
		bson.M{"$set": bson.M{"password_hash": hash, "updated_at": now}},
	)
	if err != nil {
		s.logger.WithError(err).Error("Failed to update password via reset")
		return ErrInternal
	}

	if err := s.RevokeAllUserTokens(ctx, reset.UserID); err != nil {
		s.logger.WithError(err).Error("Failed to revoke sessions after password reset")
	}
	s.logger.WithField("user_id", reset.UserID).Info("Password reset completed")
	return nil
}

func passwordResetTokenHash(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
