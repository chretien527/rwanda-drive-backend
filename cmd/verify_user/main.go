package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/0xEmmyb2/CipherPass/internal/config"
	"github.com/0xEmmyb2/CipherPass/pkg/database"
	"go.mongodb.org/mongo-driver/bson"
)

// main verifies a user's email directly in the database
// Useful for development, testing, and manual administrative verification
func main() {
	if len(os.Args) < 2 && os.Getenv("VERIFY_EMAIL") == "" {
		fmt.Println("Usage: go run cmd/verify_user/main.go <email>")
		fmt.Println("   or: VERIFY_EMAIL=<email> go run cmd/verify_user/main.go")
		os.Exit(1)
	}

	targetEmail := os.Getenv("VERIFY_EMAIL")
	if len(os.Args) >= 2 {
		targetEmail = os.Args[1]
	}

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	logger := config.NewLogger(cfg.Environment)
	db, err := database.NewMongoDB(cfg, logger)
	if err != nil {
		logger.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := db.Collection("users").UpdateOne(
		ctx,
		bson.M{"email": targetEmail},
		bson.M{"$set": bson.M{"email_verified": true, "updated_at": time.Now()}},
	)
	if err != nil {
		logger.Fatalf("Failed to update user: %v", err)
	}

	if result.MatchedCount == 0 {
		logger.Warnf("No user found with email: %s", targetEmail)
		os.Exit(1)
	}

	logger.Infof("✅ Successfully verified email for user: %s (Matched: %d, Modified: %d)", targetEmail, result.MatchedCount, result.ModifiedCount)
}
