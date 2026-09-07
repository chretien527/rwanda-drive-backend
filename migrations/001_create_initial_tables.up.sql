-- Create users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    phone VARCHAR(20),
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL CHECK (role IN ('DRIVER', 'OFFICER', 'ADMIN', 'SUPER_ADMIN')),
    document_verified BOOLEAN NOT NULL DEFAULT FALSE,
    biometric_verified BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMPTZ,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ
);

-- Create indexes for users table
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_users_active ON users(is_active);

-- Create QR active tokens table (as specified in documentation)
CREATE TABLE qr_active_tokens (
    credential_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    nonce BYTEA NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    CONSTRAINT one_active_per_credential UNIQUE (credential_id)
);

-- Create index for QR tokens
CREATE INDEX idx_qr_active_tokens_issued_at ON qr_active_tokens(issued_at);
CREATE INDEX idx_qr_active_tokens_consumed_at ON qr_active_tokens(consumed_at);

-- Create refreshed_at trigger function for users table
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
   NEW.updated_at = NOW();
   RETURN NEW;
END;
$$ language 'plpgsql';

-- Create trigger to automatically update updated_at
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();