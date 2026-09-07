package vehicle

import (
	"encoding/json"
	"net/http"

	"github.com/0xEmmyb2/CipherPass/internal/auth"
	"github.com/0xEmmyb2/CipherPass/internal/config"
	"github.com/gorilla/mux"
)

// Handler provides HTTP endpoints for vehicle operations
type Handler struct {
	service *Service
	logger  config.LoggerInterface
}

// NewHandler creates a new vehicle handler
func NewHandler(service *Service, logger config.LoggerInterface) *Handler {
	return &Handler{
		service: service,
		logger:  logger,
	}
}

// RegisterRoutes adds vehicle routes to the router
func (h *Handler) RegisterRoutes(r *mux.Router, authMiddleware *auth.Middleware) {
	vehicleRouter := r.PathPrefix("/api/v1/vehicles").Subrouter()
	vehicleRouter.Use(authMiddleware.Authenticate)
	// Drivers can manage their own vehicles
	vehicleRouter.Use(authMiddleware.RequireRole(auth.RoleDriver))

	vehicleRouter.HandleFunc("", h.HandleAddVehicle).Methods("POST")
	vehicleRouter.HandleFunc("", h.HandleGetVehicles).Methods("GET")
}

// --- Request/Response types ---

type addVehicleRequest struct {
	PlateNumber     string `json:"plate_number"`
	Make            string `json:"make"`
	Model           string `json:"model"`
	Year            int    `json:"year"`
	Color           string `json:"color"`
	ChassisNumber   string `json:"chassis_number"`
	EngineCapacity  string `json:"engine_capacity"`
	Category        string `json:"category"` // CAR, MOTORCYCLE, TRUCK, BUS
}

// --- Handlers ---

// HandleAddVehicle creates a new vehicle
func (h *Handler) HandleAddVehicle(w http.ResponseWriter, r *http.Request) {
	var req addVehicleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST")
		return
	}

	// Validate required fields
	if req.PlateNumber == "" {
		writeError(w, http.StatusBadRequest, "plate_number is required", "BAD_REQUEST")
		return
	}
	if req.Make == "" {
		writeError(w, http.StatusBadRequest, "make is required", "BAD_REQUEST")
		return
	}
	if req.Model == "" {
		writeError(w, http.StatusBadRequest, "model is required", "BAD_REQUEST")
		return
	}
	if req.Year <= 0 {
		writeError(w, http.StatusBadRequest, "year must be a positive integer", "BAD_REQUEST")
		return
	}
	if req.Color == "" {
		writeError(w, http.StatusBadRequest, "color is required", "BAD_REQUEST")
		return
	}
	if req.ChassisNumber == "" {
		writeError(w, http.StatusBadRequest, "chassis_number is required", "BAD_REQUEST")
		return
	}
	if req.EngineCapacity == "" {
		writeError(w, http.StatusBadRequest, "engine_capacity is required", "BAD_REQUEST")
		return
	}
	if req.Category == "" {
		writeError(w, http.StatusBadRequest, "category is required", "BAD_REQUEST")
		return
	}

	// Validate category
	validCategories := map[string]bool{
		"CAR": true, "MOTORCYCLE": true, "TRUCK": true, "BUS": true,
	}
	if !validCategories[req.Category] {
		writeError(w, http.StatusBadRequest, "category must be one of: CAR, MOTORCYCLE, TRUCK, BUS", "BAD_REQUEST")
		return
	}

	// Get user ID from context
	userID := auth.GetUserID(r.Context())
	if userID == "" {
		writeError(w, http.StatusUnauthorized, "user not authenticated", "AUTH_NOT_AUTHENTICATED")
		return
	}

	// Prepare vehicle data for service
	vehicleData := map[string]interface{}{
		"plateNumber":   req.PlateNumber,
		"make":          req.Make,
		"model":         req.Model,
		"year":          req.Year,
		"color":         req.Color,
		"chassisNumber": req.ChassisNumber,
		"engineCapacity":req.EngineCapacity,
		"category":      req.Category,
	}

	vehicle, err := h.service.AddVehicle(r.Context(), userID, vehicleData)
	if err != nil {
		h.logger.WithError(err).Error("Failed to add vehicle")
		writeError(w, http.StatusInternalServerError, "failed to add vehicle", "VEHICLE_CREATE_FAILED")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(vehicle)
}

// HandleGetVehicles returns all vehicles for the authenticated user
func (h *Handler) HandleGetVehicles(w http.ResponseWriter, r *http.Request) {
	userID := auth.GetUserID(r.Context())
	if userID == "" {
		writeError(w, http.StatusUnauthorized, "user not authenticated", "AUTH_NOT_AUTHENTICATED")
		return
	}

	vehicles, err := h.service.GetVehiclesByUserID(r.Context(), userID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get vehicles")
		writeError(w, http.StatusInternalServerError, "failed to get vehicles", "VEHICLE_FETCH_FAILED")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(vehicles)
}

// writeError sends a JSON error response.
func writeError(w http.ResponseWriter, status int, message, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error": message,
		"code":  code,
	})
}