package database

import (
	"context"
	"time"

	"github.com/0xEmmyb2/CipherPass/internal/config"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type MongoDB struct {
	Client   *mongo.Client
	Database *mongo.Database
	logger   config.LoggerInterface
}

func NewMongoDB(cfg *config.Config, logger config.LoggerInterface) (*MongoDB, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(cfg.Database.URI))
	if err != nil {
		return nil, err
	}
	if err := client.Ping(ctx, nil); err != nil {
		_ = client.Disconnect(ctx)
		return nil, err
	}

	db := &MongoDB{
		Client:   client,
		Database: client.Database(cfg.Database.Name),
		logger:   logger,
	}
	if err := db.EnsureIndexes(ctx); err != nil {
		_ = client.Disconnect(ctx)
		return nil, err
	}

	return db, nil
}

func (db *MongoDB) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return db.Client.Disconnect(ctx)
}

func (db *MongoDB) Ping(ctx context.Context) error {
	return db.Client.Ping(ctx, nil)
}

func (db *MongoDB) Collection(name string) *mongo.Collection {
	return db.Database.Collection(name)
}

func (db *MongoDB) EnsureIndexes(ctx context.Context) error {
	indexes := map[string][]mongo.IndexModel{
		"users": {
			{Keys: bson.D{{Key: "email", Value: 1}}, Options: options.Index().SetUnique(true)},
		},
		"refresh_tokens": {
			{Keys: bson.D{{Key: "token_hash", Value: 1}}, Options: options.Index().SetUnique(true)},
			{Keys: bson.D{{Key: "user_id", Value: 1}, {Key: "created_at", Value: -1}}},
		},
		"email_verifications": {
			{Keys: bson.D{{Key: "token_hash", Value: 1}}, Options: options.Index().SetUnique(true)},
			{Keys: bson.D{{Key: "user_id", Value: 1}, {Key: "created_at", Value: -1}}},
		},
		"password_resets": {
			{Keys: bson.D{{Key: "token_hash", Value: 1}}, Options: options.Index().SetUnique(true)},
			{Keys: bson.D{{Key: "user_id", Value: 1}, {Key: "created_at", Value: -1}}},
		},
		"phone_otps": {
			{Keys: bson.D{{Key: "user_id", Value: 1}, {Key: "purpose", Value: 1}, {Key: "created_at", Value: -1}}},
		},
		"invite_tokens": {
			{Keys: bson.D{{Key: "token_hash", Value: 1}}, Options: options.Index().SetUnique(true)},
		},
		"vehicles": {
			{Keys: bson.D{{Key: "user_id", Value: 1}, {Key: "created_at", Value: -1}}},
			{Keys: bson.D{{Key: "plate_number", Value: 1}}, Options: options.Index().SetUnique(true)},
		},
		"qr_active_tokens": {
			{Keys: bson.D{{Key: "credential_id", Value: 1}}, Options: options.Index().SetUnique(true)},
		},
		"license_leaves": {
			{Keys: bson.D{{Key: "keccak256_leaf", Value: 1}}, Options: options.Index().SetUnique(true)},
			{Keys: bson.D{{Key: "user_id", Value: 1}}},
			{Keys: bson.D{{Key: "issued_at", Value: -1}}},
		},
		"shadow_merkle_nodes": {
			{Keys: bson.D{{Key: "level", Value: 1}, {Key: "position", Value: 1}}, Options: options.Index().SetUnique(true)},
		},
	}

	for collection, models := range indexes {
		if len(models) == 0 {
			continue
		}
		if _, err := db.Collection(collection).Indexes().CreateMany(ctx, models); err != nil {
			return err
		}
	}

	zeroRoot := make([]byte, 32)
	now := time.Now()
	_, err := db.Collection("shadow_merkle_state").UpdateOne(ctx,
		bson.M{"_id": "default"},
		bson.M{"$setOnInsert": bson.M{"root": zeroRoot, "next_index": int64(0), "updated_at": now}},
		options.Update().SetUpsert(true),
	)
	return err
}
