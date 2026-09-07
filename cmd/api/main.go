package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/0xEmmyb2/CipherPass/internal/auth"
	"github.com/0xEmmyb2/CipherPass/internal/chain"
	"github.com/0xEmmyb2/CipherPass/internal/config"
	"github.com/0xEmmyb2/CipherPass/internal/qrcredentials"
	"github.com/0xEmmyb2/CipherPass/internal/server"
	"github.com/0xEmmyb2/CipherPass/internal/vehicle"
	"github.com/0xEmmyb2/CipherPass/pkg/database"
)

func main() {
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

	authService := auth.NewService(db, logger, cfg)
	inviteService := auth.NewInviteService(authService)
	authMiddleware := auth.NewMiddleware(authService, logger)

	// Rate limiters ready for per-IP enforcement (currently account lockout is primary defense)

	qrService := qrcredentials.NewQRCredentialService(db, logger, cfg)

	var chainService *chain.Service
	var chainListener *chain.EventListener
	signer, err := initSigner(cfg)
	if err != nil {
		logger.Warnf("Chain signer not available: %v", err)
	} else {
		chainService, err = chain.NewService(db, logger, cfg.Chain, signer)
		if err != nil {
			logger.Warnf("Chain service not available: %v", err)
		} else {
			chainListener = chain.NewEventListener(chainService, logger)
			chainListener.Start(context.Background())
		}
	}

	srv, err := server.NewServer(cfg, logger)
	if err != nil {
		logger.Fatalf("Failed to create server: %v", err)
	}

	authHandler := auth.NewAuthHandler(authService, inviteService, authMiddleware, logger)
	authHandler.RegisterRoutes(srv.Router)

	qrHandler := qrcredentials.NewQRHandler(qrService, chainService, authMiddleware, logger)
	qrHandler.RegisterRoutes(srv.Router)

	vehicleService := vehicle.NewService(db, logger)
	vehicleHandler := vehicle.NewHandler(vehicleService, logger)
	vehicleHandler.RegisterRoutes(srv.Router, authMiddleware)
	logger.Info("Vehicle endpoints registered")

	if chainService != nil {
		chainHandler := chain.NewHandler(chainService, logger)
		chainHandler.RegisterRoutes(srv.Router, authMiddleware)
		logger.Info("Admin chain endpoints registered")
	}

	go func() {
		logger.Infof("Starting server on %s", cfg.Server.Address)
		if err := srv.Start(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("Server failed to start: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit
	logger.Info("Shutting down server...")
	if chainListener != nil {
		chainListener.Stop()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Stop(ctx); err != nil {
		logger.Fatalf("Server forced to shutdown: %v", err)
	}
	logger.Info("Server exited")
}

func initSigner(cfg *config.Config) (chain.Signer, error) {
	switch cfg.Chain.KMS.Provider {
	case "local":
		if cfg.Chain.KMS.LocalKey == "" {
			return nil, fmt.Errorf("KMS_LOCAL_KEY must be set for local signer")
		}
		signer, err := chain.NewLocalSigner(cfg.Chain.KMS.LocalKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create local signer: %w", err)
		}
		log.Printf("Platform signer address: %s", signer.Address().Hex())
		return signer, nil
	case "aws", "gcp":
		signer, err := chain.NewKMSSigner(cfg.Chain.KMS.KeyID, cfg.Chain.KMS.Region, cfg.Chain.KMS.Provider)
		if err != nil {
			return nil, fmt.Errorf("failed to create KMS signer: %w", err)
		}
		return signer, nil
	default:
		return nil, fmt.Errorf("unknown KMS provider: %s", cfg.Chain.KMS.Provider)
	}
}
