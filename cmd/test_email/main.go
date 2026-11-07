package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/0xEmmyb2/CipherPass/internal/auth"
	"github.com/0xEmmyb2/CipherPass/internal/config"
	"github.com/joho/godotenv"
)

func main() {
	// Load .env file
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables")
	}

	toEmail := flag.String("to", "", "Email address to send test OTP to (required)")
	flag.Parse()

	if *toEmail == "" {
		fmt.Println("Usage: go run cmd/test_email/main.go -to your-email@example.com")
		os.Exit(1)
	}

	// Initialize logger
	logger := config.NewLogger(os.Getenv("LOG_LEVEL"))

	// Create email service
	emailService := auth.NewEmailService(logger)

	// Check if configured
	if !emailService.IsConfigured() {
		logger.Error("Email service is NOT configured!")
		logger.Info("Please set either RESEND_API_KEY or SMTP credentials in your .env file")
		logger.Info("See docs/EMAIL_SETUP.md for instructions")
		os.Exit(1)
	}

	logger.Info("Email service is configured ✓")
	logger.Infof("Sending test verification OTP to: %s", *toEmail)

	// Generate a test OTP
	testOTP := "123456"

	// Send verification email
	err := emailService.SendVerificationOTP(*toEmail, testOTP)
	if err != nil {
		logger.WithError(err).Error("Failed to send verification OTP")
		os.Exit(1)
	}

	logger.Info("✅ Verification email sent successfully!")
	logger.Infof("Check your inbox at: %s", *toEmail)
	logger.Infof("Test OTP code: %s", testOTP)

	// Also test password reset email
	logger.Info("\nSending test password reset OTP...")
	err = emailService.SendPasswordResetOTP(*toEmail, "654321")
	if err != nil {
		logger.WithError(err).Error("Failed to send password reset OTP")
		os.Exit(1)
	}

	logger.Info("✅ Password reset email sent successfully!")
	logger.Info("\n🎉 All email tests passed! Your email configuration is working correctly.")
}
