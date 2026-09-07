package vehicle

import (
	"context"
	"errors"
	"time"

	"github.com/0xEmmyb2/CipherPass/internal/config"
	"github.com/0xEmmyb2/CipherPass/pkg/database"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Service provides vehicle management operations
type Service struct {
	db     *database.MongoDB
	logger config.LoggerInterface
}

// NewService creates a new vehicle service
func NewService(db *database.MongoDB, logger config.LoggerInterface) *Service {
	return &Service{
		db:     db,
		logger: logger,
	}
}

// Vehicle represents a vehicle in the system
type Vehicle struct {
	ID                 string    `json:"id" bson:"id"`
	UserID             string    `json:"user_id" bson:"user_id"`
	PlateNumber        string    `json:"plate_number" bson:"plate_number"`
	Make               string    `json:"make" bson:"make"`
	Model              string    `json:"model" bson:"model"`
	Year               int       `json:"year" bson:"year"`
	Color              string    `json:"color" bson:"color"`
	ChassisNumber      string    `json:"chassis_number" bson:"chassis_number"`
	EngineCapacity     string    `json:"engine_capacity" bson:"engine_capacity"`
	Category           string    `json:"category" bson:"category"`                       // CAR, MOTORCYCLE, TRUCK, BUS
	RegistrationStatus string    `json:"registration_status" bson:"registration_status"` // ACTIVE, PENDING, EXPIRED
	InsuranceStatus    string    `json:"insurance_status" bson:"insurance_status"`       // VALID, EXPIRING_SOON, EXPIRED
	InspectionStatus   string    `json:"inspection_status" bson:"inspection_status"`     // VALID, EXPIRING_SOON, EXPIRED
	DocumentsCount     int       `json:"documents_count" bson:"documents_count"`
	CreatedAt          time.Time `json:"created_at" bson:"created_at"`
	UpdatedAt          time.Time `json:"updated_at" bson:"updated_at"`
}

// AddVehicle creates a new vehicle record
func (s *Service) AddVehicle(ctx context.Context, userID string, vehicleData map[string]interface{}) (*Vehicle, error) {
	// Extract and validate required fields
	plateNumber, okPlate := vehicleData["plateNumber"].(string)
	if !okPlate || plateNumber == "" {
		return nil, errors.New("plate_number is required")
	}
	make, okMake := vehicleData["make"].(string)
	if !okMake || make == "" {
		return nil, errors.New("make is required")
	}
	model, okModel := vehicleData["model"].(string)
	if !okModel || model == "" {
		return nil, errors.New("model is required")
	}
	year, okYear := vehicleData["year"].(int)
	if !okYear || year <= 0 {
		return nil, errors.New("year is required and must be a number")
	}
	color, okColor := vehicleData["color"].(string)
	if !okColor || color == "" {
		return nil, errors.New("color is required")
	}
	chassisNumber, okChassis := vehicleData["chassisNumber"].(string)
	if !okChassis || chassisNumber == "" {
		return nil, errors.New("chassis_number is required")
	}
	engineCapacity, okEngine := vehicleData["engineCapacity"].(string)
	if !okEngine || engineCapacity == "" {
		return nil, errors.New("engine_capacity is required")
	}
	category, okCategory := vehicleData["category"].(string)
	if !okCategory || category == "" {
		return nil, errors.New("category is required")
	}

	// Validate category
	validCategories := map[string]bool{
		"CAR": true, "MOTORCYCLE": true, "TRUCK": true, "BUS": true,
	}
	if !validCategories[category] {
		return nil, errors.New("category must be one of: CAR, MOTORCYCLE, TRUCK, BUS")
	}

	now := time.Now()
	vehicle := &Vehicle{
		ID:                 uuid.NewString(),
		UserID:             userID,
		PlateNumber:        plateNumber,
		Make:               make,
		Model:              model,
		Year:               year,
		Color:              color,
		ChassisNumber:      chassisNumber,
		EngineCapacity:     engineCapacity,
		Category:           category,
		RegistrationStatus: "ACTIVE",
		InsuranceStatus:    "VALID",
		InspectionStatus:   "VALID",
		DocumentsCount:     0,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	_, err := s.db.Collection("vehicles").InsertOne(ctx, vehicle)
	if err != nil {
		s.logger.WithError(err).Error("Failed to create vehicle record")
		return nil, err
	}
	return vehicle, nil
}

// GetVehicleByID retrieves a vehicle by its ID for a specific user
func (s *Service) GetVehicleByID(ctx context.Context, vehicleID string, userID string) (*Vehicle, error) {
	var v Vehicle
	err := s.db.Collection("vehicles").FindOne(ctx, bson.M{"id": vehicleID, "user_id": userID}).Decode(&v)

	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, errors.New("vehicle not found")
		}
		s.logger.WithError(err).Error("Failed to query vehicle")
		return nil, err
	}

	return &v, nil
}

// GetVehiclesByUserID retrieves all vehicles for a specific user
func (s *Service) GetVehiclesByUserID(ctx context.Context, userID string) ([]Vehicle, error) {
	cursor, err := s.db.Collection("vehicles").Find(ctx,
		bson.M{"user_id": userID},
		options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}}),
	)
	if err != nil {
		s.logger.WithError(err).Error("Failed to query vehicles")
		return nil, err
	}
	defer cursor.Close(ctx)

	vehicles := []Vehicle{}
	for cursor.Next(ctx) {
		var v Vehicle
		if err := cursor.Decode(&v); err != nil {
			s.logger.WithError(err).Error("Failed to scan vehicle")
			continue
		}
		vehicles = append(vehicles, v)
	}

	if err = cursor.Err(); err != nil {
		s.logger.WithError(err).Error("Error iterating vehicle rows")
		return nil, err
	}

	return vehicles, nil
}
