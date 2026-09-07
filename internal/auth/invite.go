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

type InviteToken struct {
	ID         string     `json:"id" bson:"id"`
	Token      string     `json:"token,omitempty" bson:"-"`
	TokenHash  string     `json:"-" bson:"token_hash"`
	Role       string     `json:"role" bson:"role"`
	Email      *string    `json:"email,omitempty" bson:"email,omitempty"`
	ExpiresAt  time.Time  `json:"expires_at" bson:"expires_at"`
	AcceptedAt *time.Time `json:"accepted_at,omitempty" bson:"accepted_at,omitempty"`
	CreatedBy  string     `json:"created_by" bson:"created_by"`
	CreatedAt  time.Time  `json:"created_at" bson:"created_at"`
}

type InviteService struct {
	service *Service
}

func NewInviteService(service *Service) *InviteService {
	return &InviteService{service: service}
}

func (s *InviteService) GenerateInvite(ctx context.Context, role, email, createdBy string) (*InviteToken, error) {
	if role != RoleOfficer && role != RoleAdmin {
		return nil, ErrInvalidRole
	}

	token, err := GenerateRandomHex(32)
	if err != nil {
		s.service.logger.WithError(err).Error("Failed to generate invite token")
		return nil, ErrInternal
	}

	now := time.Now()
	var emailPtr *string
	if email != "" {
		emailPtr = &email
	}
	invite := &InviteToken{
		ID:        uuid.NewString(),
		Token:     token,
		TokenHash: inviteTokenHash(token),
		Role:      role,
		Email:     emailPtr,
		ExpiresAt: now.Add(24 * time.Hour),
		CreatedBy: createdBy,
		CreatedAt: now,
	}

	_, err = s.service.db.Collection("invite_tokens").InsertOne(ctx, invite)
	if err != nil {
		s.service.logger.WithError(err).Error("Failed to store invite token")
		return nil, ErrInternal
	}

	s.service.logger.WithFields(map[string]interface{}{"role": role, "email": email, "created_by": createdBy}).Info("Invitation token created")
	return invite, nil
}

func (s *InviteService) ValidateInvite(ctx context.Context, token string) (*InviteToken, error) {
	var invite InviteToken
	err := s.service.db.Collection("invite_tokens").FindOne(ctx, bson.M{"token_hash": inviteTokenHash(token)}).Decode(&invite)
	if err == mongo.ErrNoDocuments {
		return nil, ErrInviteNotFound
	}
	if err != nil {
		s.service.logger.WithError(err).Error("Failed to look up invite token")
		return nil, ErrInternal
	}
	if invite.AcceptedAt != nil {
		return nil, ErrInviteAlreadyUsed
	}
	if time.Now().After(invite.ExpiresAt) {
		return nil, ErrInviteNotFound
	}
	return &invite, nil
}

func (s *InviteService) AcceptInvite(ctx context.Context, token, email, phone, password string) (*User, error) {
	invite, err := s.ValidateInvite(ctx, token)
	if err != nil {
		return nil, err
	}
	if invite.Email != nil && *invite.Email != email {
		return nil, ErrInviteEmailMismatch
	}

	now := time.Now()
	result, err := s.service.db.Collection("invite_tokens").UpdateOne(ctx,
		bson.M{"id": invite.ID, "accepted_at": bson.M{"$exists": false}},
		bson.M{"$set": bson.M{"accepted_at": now}},
	)
	if err != nil {
		s.service.logger.WithError(err).Error("Failed to mark invite as accepted")
		return nil, ErrInternal
	}
	if result.MatchedCount == 0 {
		return nil, ErrInviteAlreadyUsed
	}

	user, err := s.service.CreateUser(ctx, "", email, phone, password, invite.Role)
	if err != nil {
		return nil, err
	}
	_ = s.service.MarkEmailVerified(ctx, user.ID)
	user.EmailVerified = true

	s.service.logger.WithFields(map[string]interface{}{"user_id": user.ID, "role": user.Role}).Info("Invitation accepted, user created")
	return user, nil
}

func inviteTokenHash(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
