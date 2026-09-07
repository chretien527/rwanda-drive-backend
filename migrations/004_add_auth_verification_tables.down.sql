-- Remove session tracking columns from refresh_tokens
ALTER TABLE refresh_tokens DROP COLUMN IF EXISTS device_id;
ALTER TABLE refresh_tokens DROP COLUMN IF EXISTS last_used_at;

-- Remove MFA fields from users
ALTER TABLE users DROP COLUMN IF EXISTS mfa_enabled;
ALTER TABLE users DROP COLUMN IF EXISTS mfa_secret;

-- Drop password_resets
DROP TABLE IF EXISTS password_resets;

-- Drop phone_otps
DROP TABLE IF EXISTS phone_otps;

-- Drop email_verifications
DROP TABLE IF EXISTS email_verifications;

-- Remove email_verified from users
ALTER TABLE users DROP COLUMN IF EXISTS email_verified;
