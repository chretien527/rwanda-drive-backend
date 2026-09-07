-- Drop triggers and functions
DROP TRIGGER IF EXISTS update_users_updated_at ON users;
DROP FUNCTION IF EXISTS update_updated_at_column();

-- Drop tables in reverse order (to avoid foreign key constraints)
DROP TABLE IF EXISTS qr_active_tokens;
DROP TABLE IF EXISTS users;

-- Note: Indexes are automatically dropped when tables are dropped