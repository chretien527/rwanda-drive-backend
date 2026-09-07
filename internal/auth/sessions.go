package auth

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type Session struct {
	ID         string     `json:"id"`
	UserAgent  string     `json:"user_agent"`
	IPAddress  string     `json:"ip_address"`
	DeviceID   string     `json:"device_id,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt  time.Time  `json:"expires_at"`
	IsCurrent  bool       `json:"is_current"`
}

func (s *Service) ListSessions(ctx context.Context, userID, currentRefreshTokenHash string) ([]Session, error) {
	cursor, err := s.db.Collection("refresh_tokens").Find(ctx,
		bson.M{"user_id": userID, "revoked_at": bson.M{"$exists": false}, "expires_at": bson.M{"$gt": time.Now()}},
		options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}}),
	)
	if err != nil {
		s.logger.WithError(err).Error("Failed to list sessions")
		return nil, ErrInternal
	}
	defer cursor.Close(ctx)

	sessions := []Session{}
	for cursor.Next(ctx) {
		var record refreshTokenRecord
		if err := cursor.Decode(&record); err != nil {
			s.logger.WithError(err).Error("Failed to decode session")
			continue
		}
		sessions = append(sessions, Session{
			ID:         record.ID,
			UserAgent:  record.UserAgent,
			IPAddress:  record.IPAddress,
			DeviceID:   record.DeviceID,
			CreatedAt:  record.CreatedAt,
			LastUsedAt: record.LastUsedAt,
			ExpiresAt:  record.ExpiresAt,
			IsCurrent:  record.TokenHash == currentRefreshTokenHash,
		})
	}
	if err := cursor.Err(); err != nil {
		return nil, ErrInternal
	}
	return sessions, nil
}

func (s *Service) RevokeSession(ctx context.Context, userID, sessionID string) error {
	now := time.Now()
	result, err := s.db.Collection("refresh_tokens").UpdateOne(ctx,
		bson.M{"id": sessionID, "user_id": userID, "revoked_at": bson.M{"$exists": false}},
		bson.M{"$set": bson.M{"revoked_at": now}},
	)
	if err != nil {
		s.logger.WithError(err).Error("Failed to revoke session")
		return ErrInternal
	}
	if result.MatchedCount == 0 {
		return ErrSessionNotFound
	}
	s.logger.WithFields(map[string]interface{}{"user_id": userID, "session_id": sessionID}).Info("Session revoked")
	return nil
}

func (s *Service) UpdateSessionLastUsed(ctx context.Context, tokenHash string) error {
	now := time.Now()
	_, err := s.db.Collection("refresh_tokens").UpdateOne(ctx,
		bson.M{"token_hash": tokenHash},
		bson.M{"$set": bson.M{"last_used_at": now}},
	)
	return err
}

func (s *Service) GetSessionByTokenHash(ctx context.Context, tokenHash string) (*Session, error) {
	var record refreshTokenRecord
	err := s.db.Collection("refresh_tokens").FindOne(ctx, bson.M{"token_hash": tokenHash}).Decode(&record)
	if err == mongo.ErrNoDocuments {
		return nil, ErrSessionNotFound
	}
	if err != nil {
		return nil, ErrInternal
	}
	return &Session{
		ID:         record.ID,
		UserAgent:  record.UserAgent,
		IPAddress:  record.IPAddress,
		DeviceID:   record.DeviceID,
		CreatedAt:  record.CreatedAt,
		LastUsedAt: record.LastUsedAt,
		ExpiresAt:  record.ExpiresAt,
	}, nil
}

func (s *Service) CleanExpiredSessions(ctx context.Context) error {
	now := time.Now()
	cutoff := now.Add(-7 * 24 * time.Hour)
	result, err := s.db.Collection("refresh_tokens").DeleteMany(ctx,
		bson.M{"$or": []bson.M{{"expires_at": bson.M{"$lt": now}}, {"revoked_at": bson.M{"$lt": cutoff}}}},
	)
	if err != nil {
		s.logger.WithError(err).Error("Failed to clean expired sessions")
		return err
	}
	if result.DeletedCount > 0 {
		s.logger.WithField("count", result.DeletedCount).Info("Cleaned expired sessions")
	}
	return nil
}
