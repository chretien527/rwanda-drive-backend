package auth

import (
	"fmt"
	"net/smtp"
	"os"
	"strings"

	"github.com/0xEmmyb2/CipherPass/internal/config"
)

// EmailService handles sending emails
type EmailService struct {
	smtpHost     string
	smtpPort     string
	smtpUsername string
	smtpPassword string
	fromEmail    string
	fromName     string
	logger       *config.Logger
}

// NewEmailService creates a new email service
func NewEmailService(logger *config.Logger) *EmailService {
	smtpPassword := strings.ReplaceAll(getEnvOrDefault("SMTP_PASSWORD", ""), " ", "")
	return &EmailService{
		smtpHost:     getEnvOrDefault("SMTP_HOST", "smtp.gmail.com"),
		smtpPort:     getEnvOrDefault("SMTP_PORT", "587"),
		smtpUsername: getEnvOrDefault("SMTP_USERNAME", ""),
		smtpPassword: smtpPassword,
		fromEmail:    getEnvOrDefault("SMTP_FROM_EMAIL", "noreply@rwandadrive.com"),
		fromName:     getEnvOrDefault("SMTP_FROM_NAME", "Rwanda Drive"),
		logger:       logger,
	}
}

// IsConfigured checks if email service is properly configured
func (e *EmailService) IsConfigured() bool {
	return e.smtpUsername != "" && e.smtpPassword != ""
}

// SendVerificationOTP sends a 6-digit OTP for email verification
func (e *EmailService) SendVerificationOTP(toEmail, otp string) error {
	if !e.IsConfigured() {
		e.logger.Warn("Email service not configured, skipping email send")
		e.logger.Infof("Verification OTP for %s: %s", toEmail, otp)
		return nil
	}

	subject := "Verify Your Email - Rwanda Drive"
	body := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background-color: #f8f9fa; border-radius: 10px; padding: 30px; margin-bottom: 20px;">
        <h1 style="color: #2563eb; margin-bottom: 20px;">Welcome to Rwanda Drive! 🚗</h1>
        <p style="font-size: 16px; margin-bottom: 30px;">
            Thank you for registering. Please use the verification code below to activate your account.
        </p>
        
        <div style="text-align: center; margin: 40px 0;">
            <div style="background-color: #2563eb; color: white; padding: 20px; border-radius: 10px; display: inline-block;">
                <p style="margin: 0; font-size: 14px; text-transform: uppercase; letter-spacing: 1px;">Your Verification Code</p>
                <p style="margin: 10px 0 0 0; font-size: 36px; font-weight: bold; letter-spacing: 8px; font-family: 'Courier New', monospace;">%s</p>
            </div>
        </div>
        
        <p style="font-size: 16px; text-align: center; margin: 30px 0;">
            Enter this 6-digit code in the verification form.
        </p>
        
        <hr style="border: none; border-top: 1px solid #dee2e6; margin: 30px 0;">
        
        <p style="font-size: 14px; color: #666;">
            <strong>Important:</strong>
        </p>
        <ul style="font-size: 14px; color: #666;">
            <li>This code will expire in <strong>24 hours</strong></li>
            <li>Don't share this code with anyone</li>
            <li>If you didn't create an account, please ignore this email</li>
        </ul>
        
        <p style="font-size: 12px; color: #999; margin-top: 20px;">
            Having trouble? Contact our support team or try registering again.
        </p>
    </div>
    
    <p style="font-size: 12px; color: #999; text-align: center;">
        © 2026 Rwanda Drive. All rights reserved.
    </p>
</body>
</html>
`, otp)

	return e.sendEmail(toEmail, subject, body)
}

// SendPasswordResetOTP sends a 6-digit OTP for password reset
func (e *EmailService) SendPasswordResetOTP(toEmail, otp string) error {
	if !e.IsConfigured() {
		e.logger.Warn("Email service not configured, skipping email send")
		e.logger.Infof("Password reset OTP for %s: %s", toEmail, otp)
		return nil
	}

	subject := "Password Reset Code - Rwanda Drive"
	body := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background-color: #f8f9fa; border-radius: 10px; padding: 30px; margin-bottom: 20px;">
        <h1 style="color: #dc2626; margin-bottom: 20px;">Password Reset Request 🔒</h1>
        <p style="font-size: 16px; margin-bottom: 30px;">
            We received a request to reset your password. Use the verification code below to create a new password.
        </p>
        
        <div style="text-align: center; margin: 40px 0;">
            <div style="background-color: #dc2626; color: white; padding: 20px; border-radius: 10px; display: inline-block;">
                <p style="margin: 0; font-size: 14px; text-transform: uppercase; letter-spacing: 1px;">Reset Verification Code</p>
                <p style="margin: 10px 0 0 0; font-size: 36px; font-weight: bold; letter-spacing: 8px; font-family: 'Courier New', monospace;">%s</p>
            </div>
        </div>
        
        <p style="font-size: 16px; text-align: center; margin: 30px 0;">
            Enter this 6-digit code to reset your password.
        </p>
        
        <hr style="border: none; border-top: 1px solid #dee2e6; margin: 30px 0;">
        
        <p style="font-size: 14px; color: #666;">
            <strong>Important:</strong>
        </p>
        <ul style="font-size: 14px; color: #666;">
            <li>This code will expire in <strong>1 hour</strong></li>
            <li>Don't share this code with anyone</li>
            <li>If you didn't request a reset, ignore this email</li>
        </ul>
        
        <p style="font-size: 12px; color: #999; margin-top: 20px;">
            If you have concerns about your account security, please contact our support team immediately.
        </p>
    </div>
    
    <p style="font-size: 12px; color: #999; text-align: center;">
        © 2026 Rwanda Drive. All rights reserved.
    </p>
</body>
</html>
`, otp)

	return e.sendEmail(toEmail, subject, body)
}

// sendEmail sends an email using SMTP
func (e *EmailService) sendEmail(to, subject, htmlBody string) error {
	// Build SMTP authentication
	auth := smtp.PlainAuth("", e.smtpUsername, e.smtpPassword, e.smtpHost)

	// Build email message
	from := fmt.Sprintf("%s <%s>", e.fromName, e.fromEmail)
	msg := e.buildEmailMessage(from, to, subject, htmlBody)

	// Send email
	addr := fmt.Sprintf("%s:%s", e.smtpHost, e.smtpPort)
	err := smtp.SendMail(addr, auth, e.fromEmail, []string{to}, []byte(msg))
	if err != nil {
		e.logger.WithError(err).Errorf("Failed to send email to %s", to)
		return fmt.Errorf("failed to send email: %w", err)
	}

	e.logger.Infof("Email sent successfully to %s", to)
	return nil
}

// buildEmailMessage constructs the email message with headers
func (e *EmailService) buildEmailMessage(from, to, subject, htmlBody string) string {
	var msg strings.Builder
	
	msg.WriteString(fmt.Sprintf("From: %s\r\n", from))
	msg.WriteString(fmt.Sprintf("To: %s\r\n", to))
	msg.WriteString(fmt.Sprintf("Subject: %s\r\n", subject))
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	msg.WriteString("\r\n")
	msg.WriteString(htmlBody)
	
	return msg.String()
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}