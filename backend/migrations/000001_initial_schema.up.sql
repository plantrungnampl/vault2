-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Create enum types
CREATE TYPE user_role AS ENUM (
    'basic_user',
    'premium_user', 
    'team_member',
    'vault_admin',
    'security_admin',
    'super_admin'
);

CREATE TYPE user_status AS ENUM (
    'active',
    'suspended',
    'pending',
    'deleted'
);

CREATE TYPE vault_item_type AS ENUM (
    'password',
    'secure_note',
    'credit_card',
    'identity',
    'crypto_key',
    'file'
);

CREATE TYPE mfa_type AS ENUM (
    'totp',
    'webauthn',
    'sms',
    'email'
);

-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    role user_role NOT NULL DEFAULT 'basic_user',
    status user_status NOT NULL DEFAULT 'pending',
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_secret TEXT,
    mfa_backup_codes JSONB,
    login_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TIMESTAMP WITH TIME ZONE,
    last_login_at TIMESTAMP WITH TIME ZONE,
    last_login_ip INET,
    password_history JSONB,
    two_factor_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    two_factor_methods JSONB,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    email_verification_token TEXT,
    password_reset_token TEXT,
    password_reset_expiry TIMESTAMP WITH TIME ZONE,
    preferences JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMP WITH TIME ZONE
);

-- Folders table
CREATE TABLE folders (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    parent_id UUID REFERENCES folders(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    color VARCHAR(7), -- Hex color code
    icon VARCHAR(50),
    shared_with JSONB,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMP WITH TIME ZONE
);

-- Vault items table
CREATE TABLE vault_items (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    folder_id UUID REFERENCES folders(id) ON DELETE SET NULL,
    type vault_item_type NOT NULL,
    name VARCHAR(255) NOT NULL,
    data JSONB NOT NULL, -- Encrypted data
    search_tokens TEXT[], -- Encrypted search tokens
    tags TEXT[],
    favorite BOOLEAN NOT NULL DEFAULT FALSE,
    shared_with JSONB,
    last_used TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE,
    version INTEGER NOT NULL DEFAULT 1,
    history JSONB,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMP WITH TIME ZONE
);

-- Sessions table
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    refresh_token TEXT NOT NULL UNIQUE,
    ip_address INET NOT NULL,
    user_agent TEXT,
    device_info JSONB,
    last_activity TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMP WITH TIME ZONE
);

-- Audit logs table
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    resource VARCHAR(100) NOT NULL,
    resource_id UUID,
    details JSONB,
    ip_address INET NOT NULL,
    user_agent TEXT,
    success BOOLEAN NOT NULL,
    error TEXT,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    hash_chain TEXT NOT NULL -- For tamper protection
);

-- Security policies table
CREATE TABLE security_policies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL UNIQUE,
    category VARCHAR(100) NOT NULL,
    rules JSONB NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_by UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- System configuration table
CREATE TABLE system_config (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    key VARCHAR(255) NOT NULL UNIQUE,
    value JSONB NOT NULL,
    category VARCHAR(100) NOT NULL,
    updated_by UUID NOT NULL REFERENCES users(id),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- MFA credentials table
CREATE TABLE mfa_credentials (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type mfa_type NOT NULL,
    name VARCHAR(255) NOT NULL,
    data JSONB NOT NULL, -- Encrypted credential data
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_used TIMESTAMP WITH TIME ZONE
);

-- Security incidents table
CREATE TABLE security_incidents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL, -- low, medium, high, critical
    title VARCHAR(255) NOT NULL,
    description TEXT,
    metadata JSONB,
    status VARCHAR(20) NOT NULL DEFAULT 'open', -- open, investigating, resolved, false_positive
    resolved_by UUID REFERENCES users(id),
    resolved_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create indexes for performance
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_status ON users(status);
CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_users_deleted_at ON users(deleted_at);

CREATE INDEX idx_folders_user_id ON folders(user_id);
CREATE INDEX idx_folders_parent_id ON folders(parent_id);
CREATE INDEX idx_folders_deleted_at ON folders(deleted_at);

CREATE INDEX idx_vault_items_user_id ON vault_items(user_id);
CREATE INDEX idx_vault_items_folder_id ON vault_items(folder_id);
CREATE INDEX idx_vault_items_type ON vault_items(type);
CREATE INDEX idx_vault_items_deleted_at ON vault_items(deleted_at);
CREATE INDEX idx_vault_items_search_tokens ON vault_items USING GIN(search_tokens);
CREATE INDEX idx_vault_items_tags ON vault_items USING GIN(tags);
CREATE INDEX idx_vault_items_name_trgm ON vault_items USING GIN(name gin_trgm_ops);

CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_token_hash ON sessions(token_hash);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX idx_sessions_revoked_at ON sessions(revoked_at);

CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_resource ON audit_logs(resource);
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX idx_audit_logs_success ON audit_logs(success);

CREATE INDEX idx_mfa_credentials_user_id ON mfa_credentials(user_id);
CREATE INDEX idx_mfa_credentials_type ON mfa_credentials(type);

CREATE INDEX idx_security_incidents_user_id ON security_incidents(user_id);
CREATE INDEX idx_security_incidents_type ON security_incidents(type);
CREATE INDEX idx_security_incidents_status ON security_incidents(status);
CREATE INDEX idx_security_incidents_severity ON security_incidents(severity);

-- Create triggers for updated_at columns
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_folders_updated_at BEFORE UPDATE ON folders
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_vault_items_updated_at BEFORE UPDATE ON vault_items
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_security_policies_updated_at BEFORE UPDATE ON security_policies
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Create function for audit log hash chain
CREATE OR REPLACE FUNCTION generate_audit_hash_chain()
RETURNS TRIGGER AS $$
DECLARE
    prev_hash TEXT;
    current_data TEXT;
BEGIN
    -- Get the previous hash
    SELECT hash_chain INTO prev_hash 
    FROM audit_logs 
    ORDER BY timestamp DESC 
    LIMIT 1;
    
    -- If no previous hash, use genesis hash
    IF prev_hash IS NULL THEN
        prev_hash := 'genesis';
    END IF;
    
    -- Create current data string
    current_data := CONCAT(
        NEW.user_id::TEXT,
        NEW.action,
        NEW.resource,
        NEW.resource_id::TEXT,
        NEW.details::TEXT,
        NEW.timestamp::TEXT,
        prev_hash
    );
    
    -- Generate SHA-256 hash
    NEW.hash_chain := encode(digest(current_data, 'sha256'), 'hex');
    
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER audit_logs_hash_chain BEFORE INSERT ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION generate_audit_hash_chain();

-- Insert default security policies
INSERT INTO security_policies (name, category, rules, created_by) VALUES
(
    'Password Policy',
    'authentication',
    '{
        "min_length": 14,
        "require_uppercase": true,
        "require_lowercase": true,
        "require_numbers": true,
        "require_special_chars": true,
        "password_history": 24,
        "max_age_days": 90
    }',
    (SELECT id FROM users WHERE role = 'super_admin' LIMIT 1)
),
(
    'Account Lockout Policy',
    'authentication',
    '{
        "max_failed_attempts": 5,
        "lockout_duration_minutes": 30,
        "progressive_lockout": true
    }',
    (SELECT id FROM users WHERE role = 'super_admin' LIMIT 1)
),
(
    'Session Policy',
    'session_management',
    '{
        "max_session_duration_minutes": 480,
        "idle_timeout_minutes": 30,
        "max_concurrent_sessions": 3,
        "require_mfa_for_sensitive_actions": true
    }',
    (SELECT id FROM users WHERE role = 'super_admin' LIMIT 1)
),
(
    'Rate Limiting Policy',
    'security',
    '{
        "api_requests_per_minute": 100,
        "login_attempts_per_minute": 5,
        "password_reset_per_hour": 3
    }',
    (SELECT id FROM users WHERE role = 'super_admin' LIMIT 1)
);

-- Insert default system configuration
INSERT INTO system_config (key, value, category, updated_by) VALUES
(
    'vault_limits',
    '{
        "basic_user_max_items": 100,
        "premium_user_max_items": -1,
        "max_file_size_mb": 100,
        "max_shared_items": 50
    }',
    'limits',
    (SELECT id FROM users WHERE role = 'super_admin' LIMIT 1)
),
(
    'backup_settings',
    '{
        "enabled": true,
        "frequency_hours": 24,
        "retention_days": 90,
        "encryption_enabled": true
    }',
    'backup',
    (SELECT id FROM users WHERE role = 'super_admin' LIMIT 1)
),
(
    'notification_settings',
    '{
        "email_enabled": true,
        "sms_enabled": false,
        "security_alerts_enabled": true,
        "admin_notifications_enabled": true
    }',
    'notifications',
    (SELECT id FROM users WHERE role = 'super_admin' LIMIT 1)
);

-- Create row-level security policies
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE vault_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE folders ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;

-- RLS policies for users (users can only see their own data)
CREATE POLICY user_isolation ON users
    FOR ALL
    TO securevault_app_user
    USING (id = current_setting('app.current_user_id')::UUID);

-- RLS policies for vault items (users can only see their own items or shared items)
CREATE POLICY vault_item_isolation ON vault_items
    FOR ALL
    TO securevault_app_user
    USING (
        user_id = current_setting('app.current_user_id')::UUID OR
        shared_with ? current_setting('app.current_user_id')
    );

-- RLS policies for folders
CREATE POLICY folder_isolation ON folders
    FOR ALL
    TO securevault_app_user
    USING (
        user_id = current_setting('app.current_user_id')::UUID OR
        shared_with ? current_setting('app.current_user_id')
    );

-- RLS policies for sessions
CREATE POLICY session_isolation ON sessions
    FOR ALL
    TO securevault_app_user
    USING (user_id = current_setting('app.current_user_id')::UUID);

-- Create application user for row-level security
CREATE USER securevault_app_user WITH PASSWORD 'secure_random_password_here';
GRANT CONNECT ON DATABASE securevault TO securevault_app_user;
GRANT USAGE ON SCHEMA public TO securevault_app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO securevault_app_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO securevault_app_user;
