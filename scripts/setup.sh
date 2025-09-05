#!/bin/bash

# SecureVault Setup Script
# This script sets up the development environment for SecureVault

set -e

echo "🔐 SecureVault Setup Script"
echo "=========================="

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "❌ Go is not installed. Please install Go 1.21+ first."
    exit 1
fi

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install Node.js 18+ first."
    exit 1
fi

echo "✅ Prerequisites check passed"

# Create .env file if it doesn't exist
if [ ! -f backend/.env ]; then
    echo "📝 Creating backend .env file..."
    cp backend/.env.example backend/.env
    
    # Generate secure secrets
    JWT_SECRET=$(openssl rand -base64 32)
    HMAC_SECRET=$(openssl rand -base64 32)
    CSRF_SECRET=$(openssl rand -base64 32)
    DB_ENCRYPTION_KEY=$(openssl rand -base64 32)
    BACKUP_ENCRYPTION_KEY=$(openssl rand -base64 32)
    
    # Update .env file with generated secrets
    sed -i "s/your-very-secure-jwt-secret-key-change-this-to-something-random/$JWT_SECRET/g" backend/.env
    sed -i "s/your-very-secure-hmac-secret-key-change-this-to-something-random/$HMAC_SECRET/g" backend/.env
    sed -i "s/your-very-secure-csrf-secret-key-change-this-to-something-random/$CSRF_SECRET/g" backend/.env
    sed -i "s/your-very-secure-32-byte-encryption-key-here-change-this/$DB_ENCRYPTION_KEY/g" backend/.env
    sed -i "s/your-backup-encryption-key-change-this/$BACKUP_ENCRYPTION_KEY/g" backend/.env
    
    echo "✅ Backend .env file created with secure secrets"
fi

# Create frontend .env file
if [ ! -f frontend/.env ]; then
    echo "📝 Creating frontend .env file..."
    cat > frontend/.env << EOF
REACT_APP_API_URL=http://localhost:8080/api/v1
REACT_APP_ENVIRONMENT=development
REACT_APP_VERSION=1.0.0
REACT_APP_ENCRYPTION_ENABLED=true
GENERATE_SOURCEMAP=false
EOF
    echo "✅ Frontend .env file created"
fi

# Create admin dashboard .env file
if [ ! -f admin-dashboard/.env ]; then
    echo "📝 Creating admin dashboard .env file..."
    cat > admin-dashboard/.env << EOF
REACT_APP_API_URL=http://localhost:8080/api/v1
REACT_APP_ADMIN_PATH=/admin
REACT_APP_ENVIRONMENT=development
REACT_APP_VERSION=1.0.0
GENERATE_SOURCEMAP=false
EOF
    echo "✅ Admin dashboard .env file created"
fi

# Setup backend
echo "🔧 Setting up backend..."
cd backend
go mod tidy
go mod download
cd ..

# Setup frontend
echo "🔧 Setting up frontend..."
cd frontend
npm install
cd ..

# Setup admin dashboard
echo "🔧 Setting up admin dashboard..."
cd admin-dashboard
npm install
cd ..

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p logs
mkdir -p backups
mkdir -p certs
mkdir -p data/postgres
mkdir -p data/redis
mkdir -p data/elasticsearch

# Generate self-signed certificates for development
if [ ! -f certs/server.crt ]; then
    echo "🔒 Generating self-signed certificates..."
    openssl req -x509 -newkey rsa:4096 -keyout certs/server.key -out certs/server.crt -days 365 -nodes -subj "/C=US/ST=CA/L=San Francisco/O=SecureVault/CN=localhost"
    echo "✅ Certificates generated"
fi

# Create Redis configuration
if [ ! -f redis.conf ]; then
    echo "📝 Creating Redis configuration..."
    cat > redis.conf << EOF
# Redis configuration for SecureVault
bind 127.0.0.1
port 6379
timeout 0
tcp-keepalive 300
daemonize no
supervised no
pidfile /var/run/redis_6379.pid
loglevel notice
logfile ""
databases 16
always-show-logo yes
save 900 1
save 300 10
save 60 10000
stop-writes-on-bgsave-error yes
rdbcompression yes
rdbchecksum yes
dbfilename dump.rdb
dir ./
replica-serve-stale-data yes
replica-read-only yes
repl-diskless-sync no
repl-diskless-sync-delay 5
repl-ping-replica-period 10
repl-timeout 60
repl-disable-tcp-nodelay no
repl-backlog-size 1mb
repl-backlog-ttl 3600
replica-priority 100
maxmemory-policy allkeys-lru
lazyfree-lazy-eviction no
lazyfree-lazy-expire no
lazyfree-lazy-server-del no
replica-lazy-flush no
appendonly yes
appendfilename "appendonly.aof"
appendfsync everysec
no-appendfsync-on-rewrite no
auto-aof-rewrite-percentage 100
auto-aof-rewrite-min-size 64mb
aof-load-truncated yes
aof-use-rdb-preamble yes
lua-time-limit 5000
slowlog-log-slower-than 10000
slowlog-max-len 128
latency-monitor-threshold 0
notify-keyspace-events ""
hash-max-ziplist-entries 512
hash-max-ziplist-value 64
list-max-ziplist-size -2
list-compress-depth 0
set-max-intset-entries 512
zset-max-ziplist-entries 128
zset-max-ziplist-value 64
hll-sparse-max-bytes 3000
stream-node-max-bytes 4096
stream-node-max-entries 100
activerehashing yes
client-output-buffer-limit normal 0 0 0
client-output-buffer-limit replica 256mb 64mb 60
client-output-buffer-limit pubsub 32mb 8mb 60
client-query-buffer-limit 1gb
proto-max-bulk-len 512mb
hz 10
dynamic-hz yes
aof-rewrite-incremental-fsync yes
rdb-save-incremental-fsync yes
EOF
    echo "✅ Redis configuration created"
fi

# Create database initialization script
if [ ! -f init-db.sql ]; then
    echo "📝 Creating database initialization script..."
    cat > init-db.sql << EOF
-- Database initialization for SecureVault
CREATE DATABASE securevault;
CREATE USER securevault WITH PASSWORD 'securevault123';
GRANT ALL PRIVILEGES ON DATABASE securevault TO securevault;

-- Connect to the securevault database
\c securevault;

-- Grant schema permissions
GRANT ALL ON SCHEMA public TO securevault;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO securevault;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO securevault;

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
EOF
    echo "✅ Database initialization script created"
fi

# Create monitoring configuration
mkdir -p monitoring/prometheus monitoring/grafana/dashboards monitoring/grafana/datasources

if [ ! -f monitoring/prometheus.yml ]; then
    echo "📝 Creating Prometheus configuration..."
    cat > monitoring/prometheus.yml << EOF
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  # - "first_rules.yml"
  # - "second_rules.yml"

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'securevault-backend'
    static_configs:
      - targets: ['backend:8080']
    metrics_path: '/metrics'
    scrape_interval: 10s

  - job_name: 'postgres'
    static_configs:
      - targets: ['postgres:5432']

  - job_name: 'redis'
    static_configs:
      - targets: ['redis:6379']
EOF
    echo "✅ Prometheus configuration created"
fi

echo ""
echo "🎉 Setup completed successfully!"
echo ""
echo "Next steps:"
echo "1. Start the development environment:"
echo "   docker-compose up -d"
echo ""
echo "2. Run database migrations:"
echo "   cd backend && go run main.go migrate"
echo ""
echo "3. Start the backend server:"
echo "   cd backend && go run main.go"
echo ""
echo "4. Start the frontend:"
echo "   cd frontend && npm start"
echo ""
echo "5. Start the admin dashboard:"
echo "   cd admin-dashboard && npm start"
echo ""
echo "Access URLs:"
echo "- Frontend: http://localhost:3000"
echo "- Admin Dashboard: http://localhost:3001"
echo "- Backend API: http://localhost:8080"
echo "- API Documentation: http://localhost:8080/docs"
echo "- Prometheus: http://localhost:9090"
echo "- Grafana: http://localhost:3002 (admin/admin123)"
echo ""
echo "🔐 Remember to change default passwords in production!"
