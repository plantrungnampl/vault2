-- Drop all tables in reverse order of dependencies
DROP TABLE IF EXISTS security_incidents;
DROP TABLE IF EXISTS mfa_credentials;
DROP TABLE IF EXISTS system_config;
DROP TABLE IF EXISTS security_policies;
DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS vault_items;
DROP TABLE IF EXISTS folders;
DROP TABLE IF EXISTS users;

-- Drop functions
DROP FUNCTION IF EXISTS generate_audit_hash_chain();
DROP FUNCTION IF EXISTS update_updated_at_column();

-- Drop enum types
DROP TYPE IF EXISTS mfa_type;
DROP TYPE IF EXISTS vault_item_type;
DROP TYPE IF EXISTS user_status;
DROP TYPE IF EXISTS user_role;

-- Drop application user
DROP USER IF EXISTS securevault_app_user;

-- Drop extensions (only if they were created by this migration)
-- Note: In production, be careful about dropping extensions as they might be used by other applications
-- DROP EXTENSION IF EXISTS "pg_trgm";
-- DROP EXTENSION IF EXISTS "pgcrypto";
-- DROP EXTENSION IF EXISTS "uuid-ossp";
