package qrcredentials

import (
	"encoding/json"
	"net/http"

	"github.com/0xEmmyb2/CipherPass/internal/auth"
	"github.com/0xEmmyb2/CipherPass/internal/chain"
	"github.com/0xEmmyb2/CipherPass/internal/config"
	"github.com/gorilla/mux"
	"github.com/google/uuid"
	"time"
)

// QRHandler handles HTTP requests for QR credential operations
type QRHandler struct {
	service        *QRCredentialService
	chainService   *chain.Service
	authMiddleware *auth.Middleware
	logger         config.LoggerInterface
}

// NewQRHandler creates a new QR credential handler
func NewQRHandler(service *QRCredentialService, chainService *chain.Service, authMiddleware *auth.Middleware, logger config.LoggerInterface) *QRHandler {
	return &QRHandler{
		service:        service,
		chainService:   chainService,
		authMiddleware: authMiddleware,
		logger:         logger,
	}
}

// RegisterRoutes adds QR credential routes to the router
func (h *QRHandler) RegisterRoutes(r *mux.Router) {
	// Driver-authenticated routes
	driverRouter := r.PathPrefix("/api/v1/qr").Subrouter()
	driverRouter.Use(h.authMiddleware.Authenticate)
	driverRouter.Use(h.authMiddleware.RequireRole(auth.RoleDriver))
	driverRouter.HandleFunc("/refresh", h.HandleRefreshToken).Methods("POST")

	// Officer-authenticated routes
	officerRouter := r.PathPrefix("/api/v1/verification").Subrouter()
	officerRouter.Use(h.authMiddleware.Authenticate)
	officerRouter.Use(h.authMiddleware.RequireRole(auth.RoleOfficer, auth.RoleAdmin, auth.RoleSuperAdmin))
	officerRouter.HandleFunc("/scan", h.HandleVerificationScan).Methods("POST")
}

// HandleRefreshToken issues a new rotating QR token for the authenticated driver
func (h *QRHandler) HandleRefreshToken(w http.ResponseWriter, r *http.Request) {
	userID := auth.GetUserID(r.Context())

	token, err := h.service.RefreshToken(r.Context(), userID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to refresh QR token")
		writeError(w, http.StatusInternalServerError, "failed to generate QR token", "QR_REFRESH_FAILED")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"token":      token,
		"message":    "QR token refreshed. Display this to the officer for scanning.",
		"ttl":        token.ExpiresAt.Sub(token.IssuedAt).Seconds(),
		"expires_at": token.ExpiresAt,
	})
}

// HandleVerificationScan validates a QR token presented by a driver
func (h *QRHandler) HandleVerificationScan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token  string `json:"token"`
		Purpose string `json:"purpose"` // licence, insurance, registration, inspection, general
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST")
		return
	}

	if req.Token == "" {
		writeError(w, http.StatusBadRequest, "token is required", "BAD_REQUEST")
		return
	}

	// Validate and consume the token
	token, err := h.service.VerifyToken(r.Context(), req.Token)
	if err != nil {
		// Generic failure response — don't leak which specific check failed (§4 spec)
		h.logger.WithField("officer_id", auth.GetUserID(r.Context())).Warn("QR verification failed")
		writeError(w, http.StatusUnauthorized, "invalid or expired QR token", err.(Error).Code)
		return
	}

	officerID := auth.GetUserID(r.Context())

	h.logger.WithFields(map[string]interface{}{
		"officer_id":    officerID,
		"credential_id": token.CredentialID,
		"purpose":       req.Purpose,
	}).Info("QR verification successful")

	// Initialize response data
	response := map[string]interface{}{
		"verified":     true,
		"credential_id": token.CredentialID,
		"purpose":      req.Purpose,
		"verified_at":  token.IssuedAt,
		"message":      "QR credential verified successfully",
	}

	// If this is a license verification request and chain service is available, generate ZK proof
	if req.Purpose == "licence" && h.chainService != nil {
		// Convert credentialID string to UUID
		credentialUUID, err := uuid.Parse(token.CredentialID)
		if err != nil {
			h.logger.WithError(err).Warn("Failed to parse credential ID as UUID")
			// Continue without proof - don't fail the entire verification
		} else {
			// Generate ZK proof for license verification
			// For requiredCategory, we'll use a default of 2 (car) - in a real implementation,
			// this would come from the license data or be configurable
			requiredCategory := int64(2)
			currentTimestamp := time.Now().Unix()

			proof, publicWitness, err := h.chainService.GenerateLicenseVerificationProof(
				r.Context(),
				credentialUUID,
				requiredCategory,
				currentTimestamp,
			)
			if err != nil {
				h.logger.WithError(err).Warn("Failed to generate license verification proof")
				// Continue without proof - don't fail the entire verification
			} else {
				_ = proof
				_ = publicWitness
				response["proof_generated"] = false
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func writeError(w http.ResponseWriter, status int, message, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error": message,
		"code":  code,
	})
}
