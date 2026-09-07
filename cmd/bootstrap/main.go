package main

import (
	"context"
	"log"
	"os"

	"github.com/0xEmmyb2/CipherPass/internal/auth"
	"github.com/0xEmmyb2/CipherPass/internal/config"
	"github.com/0xEmmyb2/CipherPass/pkg/database"
)

// bootstrap creates the initial SUPER_ADMIN account
// This should be run only once during initial setup, never exposed over HTTP
func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize logger
	logger := config.NewLogger(cfg.Environment)

	// Initialize database connection
	db, err := database.NewMongoDB(cfg, logger)
	if err != nil {
		logger.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Create auth service
	ctx := context.Background()
	authService := auth.NewService(db, logger, cfg)

	// Check environment for SUPER_ADMIN credentials
	superAdminEmail := os.Getenv("SUPER_ADMIN_EMAIL")
	superAdminPassword := os.Getenv("SUPER_ADMIN_PASSWORD")
	superAdminPhone := os.Getenv("SUPER_ADMIN_PHONE")

	if superAdminEmail == "" || superAdminPassword == "" {
		logger.Info("SUPER_ADMIN credentials not set in environment. Skipping bootstrap.")
		logger.Info("To create SUPER_ADMIN, set SUPER_ADMIN_EMAIL and SUPER_ADMIN_PASSWORD environment variables.")
		return
	}

	logger.Info("Creating SUPER_ADMIN account...")

	// Check if user already exists
	existing, _ := authService.GetUserByEmail(ctx, superAdminEmail)
	if existing != nil {
		logger.Warn("SUPER_ADMIN account already exists. Skipping.")
		return
	}

	// Create the SUPER_ADMIN user
	user, err := authService.CreateUser(ctx, "Super Admin", superAdminEmail, superAdminPhone, superAdminPassword, auth.RoleSuperAdmin)
	if err != nil {
		logger.Fatalf("Failed to create SUPER_ADMIN: %v", err)
	}

	logger.Infof("SUPER_ADMIN account created successfully (ID: %s, Email: %s)", user.ID, user.Email)
}
