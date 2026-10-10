package auth

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"os"
	"strings"
	"time"

	"github.com/0xEmmyb2/CipherPass/internal/config"
)

// smtpTimeout bounds the whole SMTP exchange so a blocked port or slow server
// never hangs an HTTP request indefinitely.
const smtpTimeout = 20 * time.Second

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
	smtpPassword := strings.ReplaceAll(strings.TrimSpace(getEnvOrDefault("SMTP_PASSWORD", "")), " ", "")
	smtpUsername := strings.TrimSpace(getEnvOrDefault("SMTP_USERNAME", ""))

	smtpHost := strings.TrimSpace(getEnvOrDefault("SMTP_HOST", "smtp.gmail.com"))
	if strings.Contains(smtpHost, "@") {
		// Common misconfiguration: an email address was put in SMTP_HOST.
		logger.Warnf("SMTP_HOST %q looks like an email address, not a server hostname; falling back to smtp.gmail.com", smtpHost)
		smtpHost = "smtp.gmail.com"
	}
	smtpPort := strings.TrimSpace(getEnvOrDefault("SMTP_PORT", "587"))
	fromEmail := getEnvOrDefault("SMTP_FROM_EMAIL", "")
	if fromEmail == "" {
		if smtpUsername != "" {
			fromEmail = smtpUsername
		} else {
			fromEmail = "noreply@rwandadrive.com"
		}
	} else if fromEmail == "noreply@rwandadrive.com" && smtpUsername != "" && strings.Contains(smtpUsername, "@gmail.com") {
		// Gmail strictly requires the sender to match the authenticated Gmail account
		fromEmail = smtpUsername
	}

	svc := &EmailService{
		smtpHost:     smtpHost,
		smtpPort:     smtpPort,
		smtpUsername: smtpUsername,
		smtpPassword: smtpPassword,
		fromEmail:    fromEmail,
		fromName:     getEnvOrDefault("SMTP_FROM_NAME", "Rwanda Drive"),
		logger:       logger,
	}

	if svc.IsConfigured() {
		logger.Infof("Email service configured: host=%s port=%s user=%s from=%s", smtpHost, smtpPort, smtpUsername, fromEmail)
	} else {
		logger.Warn("Email service NOT configured (SMTP_USERNAME/SMTP_PASSWORD missing) - OTPs will only be printed to logs")
	}
	return svc
}

// IsConfigured checks if email service is properly configured
func (e *EmailService) IsConfigured() bool {
	return e.smtpUsername != "" && e.smtpPassword != ""
}

// SendVerificationOTP sends a 6-digit OTP for email verification
func (e *EmailService) SendVerificationOTP(toEmail, otp string) error {
	if !e.IsConfigured() {
		e.logger.Warn("Email service not configured (SMTP_USERNAME/SMTP_PASSWORD missing), skipping email send")
		e.logger.Infof("==================================================")
		e.logger.Infof("🔑 DEV VERIFICATION OTP for %s: %s", toEmail, otp)
		e.logger.Infof("==================================================")
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

// sendEmail sends an email using SMTP.
// Port 465 uses implicit TLS; any other port (typically 587) uses STARTTLS.
func (e *EmailService) sendEmail(to, subject, htmlBody string) error {
	from := fmt.Sprintf("%s <%s>", mime.QEncoding.Encode("UTF-8", e.fromName), e.fromEmail)
	msg := e.buildEmailMessage(from, to, subject, htmlBody)

	if err := e.deliver(to, []byte(msg)); err != nil {
		e.logger.WithError(err).Errorf("Failed to send email to %s via %s:%s", to, e.smtpHost, e.smtpPort)
		return fmt.Errorf("failed to send email: %w", err)
	}

	e.logger.Infof("Email sent successfully to %s", to)
	return nil
}

func (e *EmailService) deliver(to string, msg []byte) error {
	addr := net.JoinHostPort(e.smtpHost, e.smtpPort)
	tlsCfg := &tls.Config{ServerName: e.smtpHost, MinVersion: tls.VersionTLS12}
	dialer := &net.Dialer{Timeout: 10 * time.Second}

	var conn net.Conn
	var err error
	if e.smtpPort == "465" {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
	} else {
		conn, err = dialer.Dial("tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("connect to %s: %w", addr, err)
	}
	_ = conn.SetDeadline(time.Now().Add(smtpTimeout))

	c, err := smtp.NewClient(conn, e.smtpHost)
	if err != nil {
		conn.Close()
		return fmt.Errorf("smtp handshake: %w", err)
	}
	defer c.Close()

	if e.smtpPort != "465" {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return fmt.Errorf("server %s does not support STARTTLS", addr)
		}
		if err = c.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("starttls: %w", err)
		}
	}

	if err = c.Auth(smtp.PlainAuth("", e.smtpUsername, e.smtpPassword, e.smtpHost)); err != nil {
		return fmt.Errorf("smtp auth failed (for Gmail use a 16-char App Password with 2FA enabled): %w", err)
	}
	if err = c.Mail(e.fromEmail); err != nil {
		return fmt.Errorf("MAIL FROM: %w", err)
	}
	if err = c.Rcpt(to); err != nil {
		return fmt.Errorf("RCPT TO: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("DATA: %w", err)
	}
	if _, err = w.Write(msg); err != nil {
		return fmt.Errorf("write body: %w", err)
	}
	if err = w.Close(); err != nil {
		return fmt.Errorf("finish body: %w", err)
	}
	return c.Quit()
}

// buildEmailMessage constructs the email message with headers
func (e *EmailService) buildEmailMessage(from, to, subject, htmlBody string) string {
	var msg strings.Builder

	domain := "rwandadrive.local"
	if at := strings.LastIndex(e.fromEmail, "@"); at >= 0 {
		domain = e.fromEmail[at+1:]
	}
	idBytes := make([]byte, 12)
	_, _ = rand.Read(idBytes)

	msg.WriteString(fmt.Sprintf("From: %s\r\n", from))
	msg.WriteString(fmt.Sprintf("To: %s\r\n", to))
	msg.WriteString(fmt.Sprintf("Subject: %s\r\n", mime.QEncoding.Encode("UTF-8", subject)))
	msg.WriteString(fmt.Sprintf("Date: %s\r\n", time.Now().Format(time.RFC1123Z)))
	msg.WriteString(fmt.Sprintf("Message-ID: <%s@%s>\r\n", hex.EncodeToString(idBytes), domain))
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