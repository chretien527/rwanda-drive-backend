-- Create vehicles table
CREATE TABLE vehicles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    plate_number VARCHAR(20) NOT NULL,
    make VARCHAR(100) NOT NULL,
    model VARCHAR(100) NOT NULL,
    year INTEGER NOT NULL CHECK (year >= 1900 AND year <= 2100),
    color VARCHAR(50) NOT NULL,
    chassis_number VARCHAR(50) NOT NULL,
    engine_capacity VARCHAR(50) NOT NULL,
    category VARCHAR(20) NOT NULL CHECK (category IN ('CAR', 'MOTORCYCLE', 'TRUCK', 'BUS')),
    registration_status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE' CHECK (registration_status IN ('ACTIVE', 'PENDING', 'EXPIRED')),
    insurance_status VARCHAR(20) NOT NULL DEFAULT 'VALID' CHECK (insurance_status IN ('VALID', 'EXPIRING_SOON', 'EXPIRED')),
    inspection_status VARCHAR(20) NOT NULL DEFAULT 'VALID' CHECK (inspection_status IN ('VALID', 'EXPIRING_SOON', 'EXPIRED')),
    documents_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Ensure plate number is unique per user (but can be reused across users over time)
    CONSTRAINT unique_user_plate UNIQUE (user_id, plate_number)
);

-- Create indexes for vehicles table
CREATE INDEX idx_vehicles_user_id ON vehicles(user_id);
CREATE INDEX idx_vehicles_plate_number ON vehicles(plate_number);
CREATE INDEX idx_vehicles_category ON vehicles(category);
CREATE INDEX idx_vehicles_registration_status ON vehicles(registration_status);
CREATE INDEX idx_vehicles_insurance_status ON vehicles(insurance_status);
CREATE INDEX idx_vehicles_inspection_status ON vehicles(inspection_status);
CREATE INDEX idx_vehicles_created_at ON vehicles(created_at);

-- Create trigger to automatically update updated_at
CREATE TRIGGER update_vehicles_updated_at BEFORE UPDATE ON vehicles
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();