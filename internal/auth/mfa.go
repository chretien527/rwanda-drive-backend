package auth

import (
	"context"
	"encoding/base32"
	"fmt"
	"strings"

	"github.com/pquerna/otp/totp"
	"go.mongodb.org/mongo-driver/bson"
)

const (
	// MFAIssuer is the name shown in authenticator apps
	MFAIssuer = "Ikizere"

	// TOTP configuration
	totpDigits    = 6
	totpPeriod    = 30 // seconds
	totpSkew      = 1  // allow 1 step skew (30s either way)
	totpAlgorithm = "SHA1" // standard TOTP uses SHA1
)

// MFASetupResult contains the data needed to display a QR code
type MFASetupResult struct {
	Secret         string `json:"secret"`
	ProvisioningURI string `json:"provisioning_uri"`
	QRCodeURI      string `json:"qr_code_uri"` // otpauth:// URI for QR generation
}

// SetupMFA generates a TOTP secret and provisioning URI for the user.
// The secret is NOT yet stored — the user must verify a code first.
func (s *Service) SetupMFA(ctx context.Context, userID string) (*MFASetupResult, error) {
	user, err := s.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	if user.MFAEnabled {
		return nil, ErrMFAAlreadyEnabled
	}

	// Generate TOTP key
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      MFAIssuer,
		AccountName: user.Email,
		Digits:      totpDigits,
		Period:      totpPeriod,
	})
	if err != nil {
		s.logger.WithError(err).Error("Failed to generate TOTP key")
		return nil, ErrInternal
	}

	return &MFASetupResult{
		Secret:          key.Secret(),
		ProvisioningURI: key.URL(),
		QRCodeURI:       key.URL(),
	}, nil
}

// ConfirmMFA verifies the first TOTP code and enables MFA for the user.
// The secret is stored only after successful verification.
func (s *Service) ConfirmMFA(ctx context.Context, userID, secret, code string) error {
	user, err := s.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}

	if user.MFAEnabled {
		return ErrMFAAlreadyEnabled
	}

	// Verify the TOTP code against the secret
	if !totp.Validate(code, secret) {
		return ErrMFAInvalidCode
	}

	// Store the secret and enable MFA
	_, err = s.db.Collection("users").UpdateOne(ctx, bson.M{"id": userID}, bson.M{"$set": bson.M{"mfa_enabled": true, "mfa_secret": secret}})
	if err != nil {
		s.logger.WithError(err).Error("Failed to enable MFA")
		return ErrInternal
	}

	s.logger.WithField("user_id", userID).Info("MFA enabled")
	return nil
}

// ValidateMFACode verifies a TOTP code during login.
func (s *Service) ValidateMFACode(ctx context.Context, userID, code string) error {
	user, err := s.GetUserByID(ctx, userID)
	if err != nil {
		s.logger.WithError(err).Error("Failed to fetch MFA status")
		return ErrInternal
	}

	if !user.MFAEnabled {
		return ErrMFANotEnabled
	}

	if user.MFASecret == nil || *user.MFASecret == "" {
		s.logger.WithField("user_id", userID).Error("MFA enabled but no secret stored")
		return ErrInternal
	}

	if !totp.Validate(code, *user.MFASecret) {
		return ErrMFAInvalidCode
	}

	return nil
}

// DisableMFA disables MFA for a user after verifying their current TOTP code and password.
func (s *Service) DisableMFA(ctx context.Context, userID, password, code string) error {
	user, err := s.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}

	if !user.MFAEnabled {
		return ErrMFANotEnabled
	}

	// Verify password
	if !CheckPasswordHash(user.PasswordHash, password) {
		return ErrInvalidCredentials
	}

	// Verify TOTP code
	if err := s.ValidateMFACode(ctx, userID, code); err != nil {
		return err
	}

	// Disable MFA
	_, err = s.db.Collection("users").UpdateOne(ctx, bson.M{"id": userID}, bson.M{"$set": bson.M{"mfa_enabled": false}, "$unset": bson.M{"mfa_secret": ""}})
	if err != nil {
		s.logger.WithError(err).Error("Failed to disable MFA")
		return ErrInternal
	}

	s.logger.WithField("user_id", userID).Info("MFA disabled")
	return nil
}

// IsMFARequired returns true if the user's role requires MFA.
func IsMFARequired(role string) bool {
	return role == RoleOfficer || role == RoleAdmin || role == RoleSuperAdmin
}

// GetMFASecret returns the TOTP secret for a user (used during setup confirmation)
func (s *Service) GetMFASecret(ctx context.Context, userID string) (string, error) {
	user, err := s.GetUserByID(ctx, userID)
	if err != nil {
		return "", ErrInternal
	}
	if user.MFASecret == nil || *user.MFASecret == "" {
		return "", ErrMFANotEnabled
	}
	return *user.MFASecret, nil
}

// GenerateMFABackupCodes generates one-time backup codes for account recovery.
// Returns the plaintext codes (shown to user once) and their hashes (stored in DB).
func GenerateMFABackupCodes(count int) (plaintext []string, hashed []string, err error) {
	plaintext = make([]string, count)
	hashed = make([]string, count)

	for i := 0; i < count; i++ {
		code, genErr := GenerateRandomBytes(4) // 8 hex characters
		if genErr != nil {
			return nil, nil, genErr
		}
		// Format as XXXX-XXXX for readability
		codeStr := fmt.Sprintf("%s-%s",
			strings.ToUpper(base32.StdEncoding.EncodeToString(code[:2])),
			strings.ToUpper(base32.StdEncoding.EncodeToString(code[2:])),
		)
		plaintext[i] = codeStr
		hash, hashErr := HashPassword(codeStr) // Reuse bcrypt for one-time codes
		if hashErr != nil {
			return nil, nil, hashErr
		}
		hashed[i] = hash
	}

	return plaintext, hashed, nil
}
