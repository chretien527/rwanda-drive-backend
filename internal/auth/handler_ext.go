package auth

import (
	"encoding/json"
	"net/http"
)

func (h *AuthHandler) HandleVerifyEmail(w http.ResponseWriter, r *http.Request) {
	var req verifyEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST"); return
	}
	if req.Token == "" { writeError(w, http.StatusBadRequest, "token is required", "BAD_REQUEST"); return }
	if err := h.service.VerifyEmail(r.Context(), req.Token); err != nil {
		code := "BAD_REQUEST"; if e, ok := err.(Error); ok { code = e.Code }
		writeError(w, http.StatusBadRequest, err.Error(), code); return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "email verified successfully"})
}

func (h *AuthHandler) HandleResendVerificationEmail(w http.ResponseWriter, r *http.Request) {
	var req resendVerificationEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST")
		return
	}
	if req.Email == "" {
		writeError(w, http.StatusBadRequest, "email is required", "BAD_REQUEST")
		return
	}
	err := h.service.ResendEmailVerificationByEmail(r.Context(), req.Email)
	if err != nil {
		code := "INTERNAL_ERROR"
		if e, ok := err.(Error); ok {
			code = e.Code
		}
		writeError(w, http.StatusTooManyRequests, err.Error(), code)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "if an account with that email exists and is unverified, a verification code has been sent"})
}

func (h *AuthHandler) HandleResendVerification(w http.ResponseWriter, r *http.Request) {
	userID := GetUserID(r.Context())
	if userID == "" { writeError(w, http.StatusUnauthorized, "not authenticated", "AUTH_NOT_AUTHENTICATED"); return }
	user, err := h.service.GetUserByID(r.Context(), userID)
	if err != nil { writeError(w, http.StatusNotFound, "user not found", "AUTH_USER_NOT_FOUND"); return }
	if user.EmailVerified { writeError(w, http.StatusConflict, "email already verified", "AUTH_EMAIL_ALREADY_VERIFIED"); return }
	token, err := h.service.ResendEmailVerification(r.Context(), userID)
	if err != nil {
		code := "INTERNAL_ERROR"; if e, ok := err.(Error); ok { code = e.Code }
		writeError(w, http.StatusTooManyRequests, err.Error(), code); return
	}
	h.logger.WithFields(map[string]interface{}{"user_id": userID, "email": user.Email, "token": token}).Info("EMAIL_VERIFICATION_TOKEN (mock email - resend)")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "verification email sent"})
}
func (h *AuthHandler) HandleSendOTP(w http.ResponseWriter, r *http.Request) {
	userID := GetUserID(r.Context())
	if userID == "" { writeError(w, http.StatusUnauthorized, "not authenticated", "AUTH_NOT_AUTHENTICATED"); return }
	var req sendOTPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST"); return
	}
	if req.Phone != "" && !validatePhoneRW(req.Phone) {
		writeError(w, http.StatusBadRequest, "invalid phone number format", "BAD_REQUEST"); return
	}
	if err := h.service.CheckPhoneOTPRateLimit(r.Context(), userID, "phone_verify"); err != nil {
		writeError(w, http.StatusTooManyRequests, "too many OTP requests", "RATE_LIMITED"); return
	}
	code, err := h.service.GeneratePhoneOTP(r.Context(), userID, "phone_verify")
	if err != nil { writeError(w, http.StatusInternalServerError, "failed to send OTP", "INTERNAL_ERROR"); return }
	h.logger.WithFields(map[string]interface{}{"user_id": userID, "phone": req.Phone, "code": code}).Info("PHONE_OTP (mock SMS)")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "verification code sent"})
}

func (h *AuthHandler) HandleVerifyOTP(w http.ResponseWriter, r *http.Request) {
	userID := GetUserID(r.Context())
	if userID == "" { writeError(w, http.StatusUnauthorized, "not authenticated", "AUTH_NOT_AUTHENTICATED"); return }
	var req verifyOTPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST"); return
	}
	if req.Code == "" { writeError(w, http.StatusBadRequest, "code is required", "BAD_REQUEST"); return }
	if err := h.service.VerifyPhoneOTP(r.Context(), userID, req.Code, "phone_verify"); err != nil {
		code := "BAD_REQUEST"; if e, ok := err.(Error); ok { code = e.Code }
		writeError(w, http.StatusBadRequest, err.Error(), code); return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "phone verified successfully"})
}
func (h *AuthHandler) HandleMFASetup(w http.ResponseWriter, r *http.Request) {
	userID := GetUserID(r.Context())
	if userID == "" { writeError(w, http.StatusUnauthorized, "not authenticated", "AUTH_NOT_AUTHENTICATED"); return }
	result, err := h.service.SetupMFA(r.Context(), userID)
	if err != nil {
		code := "INTERNAL_ERROR"; if e, ok := err.(Error); ok { code = e.Code }
		writeError(w, http.StatusBadRequest, err.Error(), code); return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(mfaSetupResponse{Secret: result.Secret, ProvisioningURI: result.ProvisioningURI})
}

func (h *AuthHandler) HandleMFAConfirm(w http.ResponseWriter, r *http.Request) {
	userID := GetUserID(r.Context())
	if userID == "" { writeError(w, http.StatusUnauthorized, "not authenticated", "AUTH_NOT_AUTHENTICATED"); return }
	var req mfaConfirmRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST"); return
	}
	if req.Secret == "" || req.Code == "" {
		writeError(w, http.StatusBadRequest, "secret and code are required", "BAD_REQUEST"); return
	}
	if err := h.service.ConfirmMFA(r.Context(), userID, req.Secret, req.Code); err != nil {
		code := "INTERNAL_ERROR"; if e, ok := err.(Error); ok { code = e.Code }
		writeError(w, http.StatusBadRequest, err.Error(), code); return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "MFA enabled successfully"})
}
func (h *AuthHandler) HandleMFAVerify(w http.ResponseWriter, r *http.Request) {
	var req mfaVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST"); return
	}
	if req.MFAToken == "" || req.Code == "" {
		writeError(w, http.StatusBadRequest, "mfa_token and code are required", "BAD_REQUEST"); return
	}
	userID, err := h.service.ValidateMFALoginToken(req.MFAToken)
	if err != nil { writeError(w, http.StatusUnauthorized, "invalid or expired MFA token", "AUTH_MFA_TOKEN_INVALID"); return }
	if err := h.service.ValidateMFACode(r.Context(), userID, req.Code); err != nil {
		code := "AUTH_MFA_INVALID_CODE"; if e, ok := err.(Error); ok { code = e.Code }
		writeError(w, http.StatusUnauthorized, err.Error(), code); return
	}
	user, err := h.service.GetUserByID(r.Context(), userID)
	if err != nil { writeError(w, http.StatusInternalServerError, "failed to complete login", "INTERNAL_ERROR"); return }
	tokens, err := h.service.GenerateTokenPair(r.Context(), user, r.Header.Get("User-Agent"), r.RemoteAddr)
	if err != nil { writeError(w, http.StatusInternalServerError, "failed to generate session", "INTERNAL_ERROR"); return }
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(loginResponse{User: userToResponse(user), Tokens: tokens})
}

func (h *AuthHandler) HandleMFADisable(w http.ResponseWriter, r *http.Request) {
	userID := GetUserID(r.Context())
	if userID == "" { writeError(w, http.StatusUnauthorized, "not authenticated", "AUTH_NOT_AUTHENTICATED"); return }
	var req mfaDisableRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST"); return
	}
	if req.Password == "" || req.Code == "" {
		writeError(w, http.StatusBadRequest, "password and code are required", "BAD_REQUEST"); return
	}
	if err := h.service.DisableMFA(r.Context(), userID, req.Password, req.Code); err != nil {
		code := "INTERNAL_ERROR"; if e, ok := err.(Error); ok { code = e.Code }
		writeError(w, http.StatusBadRequest, err.Error(), code); return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "MFA disabled successfully"})
}
