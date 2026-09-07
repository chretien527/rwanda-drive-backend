package auth

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/0xEmmyb2/CipherPass/internal/config"
	"github.com/gorilla/mux"
)

type AuthHandler struct {
	service        *Service
	inviteService  *InviteService
	authMiddleware *Middleware
	logger         config.LoggerInterface
}

func NewAuthHandler(service *Service, inviteService *InviteService, authMiddleware *Middleware, logger config.LoggerInterface) *AuthHandler {
	return &AuthHandler{
		service:        service,
		inviteService:  inviteService,
		authMiddleware: authMiddleware,
		logger:         logger,
	}
}

func (h *AuthHandler) RegisterRoutes(r *mux.Router) {
	r.HandleFunc("/api/v1/auth/register", h.HandleRegister).Methods("POST")
	r.HandleFunc("/api/v1/auth/login", h.HandleLogin).Methods("POST")
	r.HandleFunc("/api/v1/auth/refresh", h.HandleRefreshToken).Methods("POST")
	r.HandleFunc("/api/v1/auth/invite/accept", h.HandleAcceptInvite).Methods("POST")
	r.HandleFunc("/api/v1/auth/verify-email", h.HandleVerifyEmail).Methods("POST")
	r.HandleFunc("/api/v1/auth/resend-verification-email", h.HandleResendVerificationEmail).Methods("POST")
	r.HandleFunc("/api/v1/auth/password/forgot", h.HandleForgotPassword).Methods("POST")
	r.HandleFunc("/api/v1/auth/password/reset", h.HandleResetPassword).Methods("POST")
	r.HandleFunc("/api/v1/auth/mfa/verify", h.HandleMFAVerify).Methods("POST")

	authRouter := r.PathPrefix("/api/v1/auth").Subrouter()
	authRouter.Use(h.authMiddleware.Authenticate)
	authRouter.HandleFunc("/me", h.HandleGetCurrentUser).Methods("GET")
	authRouter.HandleFunc("/logout", h.HandleLogout).Methods("POST")
	authRouter.HandleFunc("/password/change", h.HandleChangePassword).Methods("POST")
	authRouter.HandleFunc("/sessions", h.HandleListSessions).Methods("GET")
	authRouter.HandleFunc("/sessions/{session_id}", h.HandleRevokeSession).Methods("DELETE")
	authRouter.HandleFunc("/resend-verification", h.HandleResendVerification).Methods("POST")
	authRouter.HandleFunc("/otp/send", h.HandleSendOTP).Methods("POST")
	authRouter.HandleFunc("/otp/verify", h.HandleVerifyOTP).Methods("POST")
	authRouter.HandleFunc("/mfa/setup", h.HandleMFASetup).Methods("POST")
	authRouter.HandleFunc("/mfa/confirm", h.HandleMFAConfirm).Methods("POST")
	authRouter.HandleFunc("/mfa/disable", h.HandleMFADisable).Methods("POST")

	adminRouter := r.PathPrefix("/api/v1/auth").Subrouter()
	adminRouter.Use(h.authMiddleware.Authenticate)
	adminRouter.Use(h.authMiddleware.RequireRole(RoleAdmin, RoleSuperAdmin))
	adminRouter.HandleFunc("/invite", h.HandleCreateInvite).Methods("POST")
}
type registerRequest struct {
	FullName string `json:"full_name"`
	Email    string `json:"email"`
	Phone    string `json:"phone,omitempty"`
	Password string `json:"password"`
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginResponse struct {
	User        *userResponse `json:"user"`
	Tokens      *TokenPair    `json:"tokens,omitempty"`
	MFARequired bool          `json:"mfa_required"`
	MFAToken    string        `json:"mfa_token,omitempty"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type inviteRequest struct {
	Role  string `json:"role"`
	Email string `json:"email"`
}

type acceptInviteRequest struct {
	Token    string `json:"token"`
	Email    string `json:"email"`
	Phone    string `json:"phone,omitempty"`
	Password string `json:"password"`
}

type verifyEmailRequest struct {
	Token string `json:"token"`
}

type resendVerificationEmailRequest struct {
	Email string `json:"email"`
}

type sendOTPRequest struct {
	Phone string `json:"phone"`
}

type verifyOTPRequest struct {
	Code string `json:"code"`
}

type changePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

type forgotPasswordRequest struct {
	Email string `json:"email"`
}

type resetPasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

type mfaSetupResponse struct {
	Secret          string `json:"secret"`
	ProvisioningURI string `json:"provisioning_uri"`
}

type mfaConfirmRequest struct {
	Secret string `json:"secret"`
	Code   string `json:"code"`
}

type mfaVerifyRequest struct {
	MFAToken string `json:"mfa_token"`
	Code     string `json:"code"`
}

type mfaDisableRequest struct {
	Password string `json:"password"`
	Code     string `json:"code"`
}

type userResponse struct {
	ID                string  `json:"id"`
	FullName          string  `json:"full_name,omitempty"`
	Email             string  `json:"email"`
	Phone             *string `json:"phone,omitempty"`
	Role              string  `json:"role"`
	EmailVerified     bool    `json:"email_verified"`
	MFAEnabled        bool    `json:"mfa_enabled"`
	DocumentVerified  bool    `json:"document_verified"`
	BiometricVerified bool    `json:"biometric_verified"`
}

func userToResponse(u *User) *userResponse {
	return &userResponse{
		ID: u.ID, FullName: u.FullName, Email: u.Email, Phone: u.Phone, Role: u.Role,
		EmailVerified: u.EmailVerified, MFAEnabled: u.MFAEnabled,
		DocumentVerified: u.DocumentVerified, BiometricVerified: u.BiometricVerified,
	}
}

func (h *AuthHandler) HandleRegister(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST")
		return
	}
	if req.Email == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "email and password are required", "BAD_REQUEST")
		return
	}
	if strings.TrimSpace(req.FullName) == "" {
		writeError(w, http.StatusBadRequest, "full name is required", "BAD_REQUEST")
		return
	}
	if len(req.Password) < 8 {
		writeError(w, http.StatusBadRequest, "password must be at least 8 characters", "BAD_REQUEST")
		return
	}
	existing, _ := h.service.GetUserByEmail(r.Context(), req.Email)
	if existing != nil {
		writeError(w, http.StatusConflict, "an account with this email already exists", "AUTH_USER_EXISTS")
		return
	}
	user, err := h.service.CreateUser(r.Context(), strings.TrimSpace(req.FullName), req.Email, req.Phone, req.Password, RoleDriver)
	if err != nil {
		h.logger.WithError(err).Error("Failed to create user")
		code := "INTERNAL_ERROR"
		if e, ok := err.(Error); ok { code = e.Code }
		writeError(w, http.StatusInternalServerError, "failed to create account", code)
		return
	}
	verificationToken, _ := h.service.GenerateEmailVerification(r.Context(), user.ID)
	if verificationToken != "" {
		h.logger.WithFields(map[string]interface{}{
			"user_id": user.ID, "email": user.Email, "token": verificationToken,
		}).Info("EMAIL_VERIFICATION_TOKEN (mock email)")
	}
	h.logger.WithField("user_id", user.ID).Info("User registered")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "registration successful. Please verify your email.", "user": userToResponse(user),
	})
}

func (h *AuthHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST")
		return
	}
	if req.Email == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "email and password are required", "BAD_REQUEST")
		return
	}
	user, err := h.service.Authenticate(r.Context(), req.Email, req.Password)
	if err != nil {
		h.logger.WithField("email", req.Email).Warn("Login failed")
		if e, ok := err.(Error); ok {
			if e.Code == "AUTH_EMAIL_NOT_VERIFIED" {
				writeError(w, http.StatusForbidden, e.Message, e.Code)
				return
			}
			writeError(w, http.StatusUnauthorized, "invalid credentials", e.Code)
		} else {
			writeError(w, http.StatusUnauthorized, "invalid credentials", "AUTH_INVALID_CREDENTIALS")
		}
		return
	}
	if IsMFARequired(user.Role) || user.MFAEnabled {
		mfaToken, mfaErr := h.service.GenerateMFALoginToken(r.Context(), user.ID)
		if mfaErr != nil {
			h.logger.WithError(mfaErr).Error("Failed to generate MFA token")
			writeError(w, http.StatusInternalServerError, "failed to initiate MFA", "INTERNAL_ERROR")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(loginResponse{User: userToResponse(user), MFARequired: true, MFAToken: mfaToken})
		return
	}
	tokens, err := h.service.GenerateTokenPair(r.Context(), user, r.Header.Get("User-Agent"), r.RemoteAddr)
	if err != nil {
		h.logger.WithError(err).Error("Failed to generate tokens")
		writeError(w, http.StatusInternalServerError, "failed to generate session", "INTERNAL_ERROR")
		return
	}
	h.logger.WithField("user_id", user.ID).Info("User logged in")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(loginResponse{User: userToResponse(user), Tokens: tokens})
}

func (h *AuthHandler) HandleRefreshToken(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST"); return
	}
	if req.RefreshToken == "" {
		writeError(w, http.StatusBadRequest, "refresh_token is required", "BAD_REQUEST"); return
	}
	tokens, err := h.service.RefreshAccessToken(r.Context(), req.RefreshToken, r.Header.Get("User-Agent"), r.RemoteAddr)
	if err != nil {
		code := "AUTH_TOKEN_INVALID"
		if e, ok := err.(Error); ok { code = e.Code }
		writeError(w, http.StatusUnauthorized, "invalid or expired refresh token", code); return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokens)
}

func (h *AuthHandler) HandleGetCurrentUser(w http.ResponseWriter, r *http.Request) {
	userID := GetUserID(r.Context())
	if userID == "" { writeError(w, http.StatusUnauthorized, "not authenticated", "AUTH_NOT_AUTHENTICATED"); return }
	user, err := h.service.GetUserByID(r.Context(), userID)
	if err != nil { writeError(w, http.StatusNotFound, "user not found", "AUTH_USER_NOT_FOUND"); return }
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userToResponse(user))
}

func (h *AuthHandler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	userID := GetUserID(r.Context())
	_ = h.service.RevokeAllUserTokens(r.Context(), userID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "logged out successfully"})
}

func (h *AuthHandler) HandleChangePassword(w http.ResponseWriter, r *http.Request) {
    userID := GetUserID(r.Context())
    if userID == "" { writeError(w, http.StatusUnauthorized, "not authenticated", "AUTH_NOT_AUTHENTICATED"); return }
    var req changePasswordRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        writeError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST"); return
    }
    if req.CurrentPassword == "" || req.NewPassword == "" {
        writeError(w, http.StatusBadRequest, "current_password and new_password are required", "BAD_REQUEST"); return
    }
    if len(req.NewPassword) < 8 {
        writeError(w, http.StatusBadRequest, "new password must be at least 8 characters", "BAD_REQUEST"); return
    }
    if err := h.service.ChangePassword(r.Context(), userID, req.CurrentPassword, req.NewPassword); err != nil {
        code := "INTERNAL_ERROR"
        if e, ok := err.(Error); ok { code = e.Code }
        writeError(w, http.StatusBadRequest, err.Error(), code); return
    }
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{"message": "password changed successfully"})
}

func (h *AuthHandler) HandleForgotPassword(w http.ResponseWriter, r *http.Request) {
    var req forgotPasswordRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        writeError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST"); return
    }
    if req.Email == "" { writeError(w, http.StatusBadRequest, "email is required", "BAD_REQUEST"); return }
    token, err := h.service.ForgotPassword(r.Context(), req.Email)
    if err != nil { writeError(w, http.StatusInternalServerError, "failed to process request", "INTERNAL_ERROR"); return }
    if token != "" {
        h.logger.WithFields(map[string]interface{}{"email": req.Email, "token": token}).Info("PASSWORD_RESET_TOKEN (mock email)")
    }
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{"message": "if an account with that email exists, a reset link has been sent"})
}

func (h *AuthHandler) HandleResetPassword(w http.ResponseWriter, r *http.Request) {
    var req resetPasswordRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        writeError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST"); return
    }
    if req.Token == "" || req.NewPassword == "" {
        writeError(w, http.StatusBadRequest, "token and new_password are required", "BAD_REQUEST"); return
    }
    if len(req.NewPassword) < 8 {
        writeError(w, http.StatusBadRequest, "password must be at least 8 characters", "BAD_REQUEST"); return
    }
    if err := h.service.ResetPassword(r.Context(), req.Token, req.NewPassword); err != nil {
        code := "INTERNAL_ERROR"
        if e, ok := err.(Error); ok { code = e.Code }
        writeError(w, http.StatusBadRequest, err.Error(), code); return
    }
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{"message": "password reset successfully"})
}

func (h *AuthHandler) HandleListSessions(w http.ResponseWriter, r *http.Request) {
    userID := GetUserID(r.Context())
    if userID == "" { writeError(w, http.StatusUnauthorized, "not authenticated", "AUTH_NOT_AUTHENTICATED"); return }
    sessions, err := h.service.ListSessions(r.Context(), userID, "")
    if err != nil { writeError(w, http.StatusInternalServerError, "failed to list sessions", "INTERNAL_ERROR"); return }
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{"sessions": sessions})
}

func (h *AuthHandler) HandleRevokeSession(w http.ResponseWriter, r *http.Request) {
    userID := GetUserID(r.Context())
    if userID == "" { writeError(w, http.StatusUnauthorized, "not authenticated", "AUTH_NOT_AUTHENTICATED"); return }
    vars := mux.Vars(r)
    sessionID := vars["session_id"]
    if sessionID == "" { writeError(w, http.StatusBadRequest, "session_id is required", "BAD_REQUEST"); return }
    if err := h.service.RevokeSession(r.Context(), userID, sessionID); err != nil {
        code := "INTERNAL_ERROR"
        if e, ok := err.(Error); ok { code = e.Code }
        writeError(w, http.StatusNotFound, err.Error(), code); return
    }
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{"message": "session revoked"})
}

func (h *AuthHandler) HandleCreateInvite(w http.ResponseWriter, r *http.Request) {
    var req inviteRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        writeError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST"); return
    }
    if req.Role != RoleOfficer && req.Role != RoleAdmin {
        writeError(w, http.StatusBadRequest, "role must be OFFICER or ADMIN", "AUTH_INVALID_ROLE"); return
    }
    createdBy := GetUserID(r.Context())
    invite, err := h.inviteService.GenerateInvite(r.Context(), req.Role, req.Email, createdBy)
    if err != nil {
        code := "INTERNAL_ERROR"
        if e, ok := err.(Error); ok { code = e.Code }
        writeError(w, http.StatusInternalServerError, "failed to create invitation", code); return
    }
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusCreated)
    json.NewEncoder(w).Encode(map[string]interface{}{"invite": invite, "message": "invitation created"})
}

func (h *AuthHandler) HandleAcceptInvite(w http.ResponseWriter, r *http.Request) {
    var req acceptInviteRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        writeError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST"); return
    }
    if req.Token == "" || req.Email == "" || req.Password == "" {
        writeError(w, http.StatusBadRequest, "token, email, and password are required", "BAD_REQUEST"); return
    }
    if len(req.Password) < 8 {
        writeError(w, http.StatusBadRequest, "password must be at least 8 characters", "BAD_REQUEST"); return
    }
    user, err := h.inviteService.AcceptInvite(r.Context(), req.Token, req.Email, req.Phone, req.Password)
    if err != nil {
        code := "BAD_REQUEST"
        if e, ok := err.(Error); ok { code = e.Code }
        writeError(w, http.StatusBadRequest, err.Error(), code); return
    }
    _ = h.service.MarkEmailVerified(r.Context(), user.ID)
    tokens, err := h.service.GenerateTokenPair(r.Context(), user, r.Header.Get("User-Agent"), r.RemoteAddr)
    if err != nil { writeError(w, http.StatusInternalServerError, "failed to generate session", "INTERNAL_ERROR"); return }
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusCreated)
    json.NewEncoder(w).Encode(map[string]interface{}{"user": userToResponse(user), "tokens": tokens})
}

func writeError(w http.ResponseWriter, status int, message, code string) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(status)
    json.NewEncoder(w).Encode(map[string]string{"error": message, "code": code})
}

func validatePhoneRW(phone string) bool {
    normalized := strings.ReplaceAll(phone, " ", "")
    normalized = strings.ReplaceAll(normalized, "-", "")
    if strings.HasPrefix(normalized, "+250") {
        normalized = normalized[4:]
    } else if strings.HasPrefix(normalized, "250") {
        normalized = normalized[3:]
    } else if strings.HasPrefix(normalized, "0") {
        normalized = normalized[1:]
    }
    if len(normalized) != 9 {
        return false
    }
    return normalized[0] == '7' || normalized[0] == '8'
}
