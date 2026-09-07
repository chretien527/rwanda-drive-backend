package auth

// Error represents an application error with a machine-readable code
type Error struct {
	Message string `json:"message"`
	Code    string `json:"code"`
}

func NewError(message, code string) Error {
	return Error{Message: message, Code: code}
}

func (e Error) Error() string {
	return e.Message
}

// Auth errors — generic messages to avoid leaking internal details
var (
	ErrUserNotFound       = NewError("invalid credentials", "AUTH_USER_NOT_FOUND")
	ErrInvalidCredentials = NewError("invalid credentials", "AUTH_INVALID_CREDENTIALS")
	ErrAccountDisabled    = NewError("account is disabled", "AUTH_ACCOUNT_DISABLED")
	ErrAccountLocked      = NewError("account is temporarily locked due to too many failed attempts", "AUTH_ACCOUNT_LOCKED")
	ErrInvalidRole        = NewError("invalid role", "AUTH_INVALID_ROLE")
	ErrForbidden          = NewError("insufficient permissions", "AUTH_FORBIDDEN")
	ErrInternal           = NewError("internal server error", "INTERNAL_ERROR")
	ErrBadRequest         = NewError("bad request", "BAD_REQUEST")
	ErrRateLimited        = NewError("too many requests, please try again later", "RATE_LIMITED")

	// Invite errors
	ErrInviteNotFound      = NewError("invitation not found or expired", "AUTH_INVITE_NOT_FOUND")
	ErrInviteAlreadyUsed   = NewError("invitation has already been used", "AUTH_INVITE_USED")
	ErrInviteEmailMismatch = NewError("invitation email does not match", "AUTH_INVITE_EMAIL_MISMATCH")

	// Token errors
	ErrTokenExpired = NewError("token has expired", "AUTH_TOKEN_EXPIRED")
	ErrTokenInvalid = NewError("invalid token", "AUTH_TOKEN_INVALID")
	ErrTokenRevoked = NewError("token has been revoked", "AUTH_TOKEN_REVOKED")

	// Email verification errors
	ErrEmailVerificationNotFound = NewError("email verification token not found or expired", "AUTH_EMAIL_VERIFY_NOT_FOUND")
	ErrEmailAlreadyVerified      = NewError("email is already verified", "AUTH_EMAIL_ALREADY_VERIFIED")
	ErrEmailVerificationExpired  = NewError("email verification token has expired", "AUTH_EMAIL_VERIFY_EXPIRED")
	ErrEmailNotVerified          = NewError("please verify your email before logging in", "AUTH_EMAIL_NOT_VERIFIED")

	// OTP errors
	ErrOTPNotFound       = NewError("verification code not found or expired", "AUTH_OTP_NOT_FOUND")
	ErrOTPInvalid        = NewError("invalid verification code", "AUTH_OTP_INVALID")
	ErrOTPExpired        = NewError("verification code has expired", "AUTH_OTP_EXPIRED")
	ErrOTPAlreadyVerified = NewError("verification code has already been used", "AUTH_OTP_ALREADY_VERIFIED")
	ErrOTPMaxAttempts    = NewError("too many incorrect attempts, please request a new code", "AUTH_OTP_MAX_ATTEMPTS")
	ErrPhoneNotVerified  = NewError("phone number not verified", "AUTH_PHONE_NOT_VERIFIED")

	// MFA errors
	ErrMFAAlreadyEnabled = NewError("multi-factor authentication is already enabled", "AUTH_MFA_ALREADY_ENABLED")
	ErrMFANotEnabled     = NewError("multi-factor authentication is not enabled", "AUTH_MFA_NOT_ENABLED")
	ErrMFAInvalidCode    = NewError("invalid authentication code", "AUTH_MFA_INVALID_CODE")
	ErrMFARequired       = NewError("multi-factor authentication is required for your role", "AUTH_MFA_REQUIRED")
	ErrMFATokenInvalid   = NewError("invalid or expired MFA session token", "AUTH_MFA_TOKEN_INVALID")

	// Password errors
	ErrPasswordResetNotFound = NewError("password reset token not found or expired", "AUTH_PASSWORD_RESET_NOT_FOUND")
	ErrPasswordResetUsed     = NewError("password reset token has already been used", "AUTH_PASSWORD_RESET_USED")
	ErrPasswordResetExpired  = NewError("password reset token has expired", "AUTH_PASSWORD_RESET_EXPIRED")

	// Session errors
	ErrSessionNotFound = NewError("session not found", "AUTH_SESSION_NOT_FOUND")
)
