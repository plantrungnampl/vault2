@echo off
REM SecureVault Setup Script for Windows
REM This script sets up the development environment for SecureVault

echo 🔐 SecureVault Setup Script
echo ==========================

REM Check if Docker is installed
docker --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Docker is not installed. Please install Docker first.
    exit /b 1
)

REM Check if Docker Compose is installed
docker-compose --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Docker Compose is not installed. Please install Docker Compose first.
    exit /b 1
)

REM Check if Go is installed
go version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Go is not installed. Please install Go 1.21+ first.
    exit /b 1
)

REM Check if Node.js is installed
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Node.js is not installed. Please install Node.js 18+ first.
    exit /b 1
)

echo ✅ Prerequisites check passed

REM Create .env file if it doesn't exist
if not exist backend\.env (
    echo 📝 Creating backend .env file...
    copy backend\.env.example backend\.env >nul
    
    REM Note: On Windows, you'll need to manually update the secrets in .env file
    echo ⚠️  Please update the secrets in backend\.env file with secure random values
    echo ✅ Backend .env file created
)

REM Create frontend .env file
if not exist frontend\.env (
    echo 📝 Creating frontend .env file...
    (
        echo REACT_APP_API_URL=http://localhost:8080/api/v1
        echo REACT_APP_ENVIRONMENT=development
        echo REACT_APP_VERSION=1.0.0
        echo REACT_APP_ENCRYPTION_ENABLED=true
        echo GENERATE_SOURCEMAP=false
    ) > frontend\.env
    echo ✅ Frontend .env file created
)

REM Create admin dashboard .env file
if not exist admin-dashboard\.env (
    echo 📝 Creating admin dashboard .env file...
    (
        echo REACT_APP_API_URL=http://localhost:8080/api/v1
        echo REACT_APP_ADMIN_PATH=/admin
        echo REACT_APP_ENVIRONMENT=development
        echo REACT_APP_VERSION=1.0.0
        echo GENERATE_SOURCEMAP=false
    ) > admin-dashboard\.env
    echo ✅ Admin dashboard .env file created
)

REM Setup backend
echo 🔧 Setting up backend...
cd backend
go mod tidy
go mod download
cd ..

REM Setup frontend
echo 🔧 Setting up frontend...
cd frontend
npm install
cd ..

REM Setup admin dashboard
echo 🔧 Setting up admin dashboard...
cd admin-dashboard
npm install
cd ..

REM Create necessary directories
echo 📁 Creating directories...
if not exist logs mkdir logs
if not exist backups mkdir backups
if not exist certs mkdir certs
if not exist data\postgres mkdir data\postgres
if not exist data\redis mkdir data\redis
if not exist data\elasticsearch mkdir data\elasticsearch

REM Create Redis configuration
if not exist redis.conf (
    echo 📝 Creating Redis configuration...
    (
        echo # Redis configuration for SecureVault
        echo bind 127.0.0.1
        echo port 6379
        echo timeout 0
        echo tcp-keepalive 300
        echo daemonize no
        echo supervised no
        echo pidfile /var/run/redis_6379.pid
        echo loglevel notice
        echo logfile ""
        echo databases 16
        echo always-show-logo yes
        echo save 900 1
        echo save 300 10
        echo save 60 10000
        echo stop-writes-on-bgsave-error yes
        echo rdbcompression yes
        echo rdbchecksum yes
        echo dbfilename dump.rdb
        echo dir ./
        echo maxmemory-policy allkeys-lru
        echo appendonly yes
        echo appendfilename "appendonly.aof"
        echo appendfsync everysec
    ) > redis.conf
    echo ✅ Redis configuration created
)

REM Create database initialization script
if not exist init-db.sql (
    echo 📝 Creating database initialization script...
    (
        echo -- Database initialization for SecureVault
        echo CREATE DATABASE securevault;
        echo CREATE USER securevault WITH PASSWORD 'securevault123';
        echo GRANT ALL PRIVILEGES ON DATABASE securevault TO securevault;
        echo.
        echo -- Connect to the securevault database
        echo \c securevault;
        echo.
        echo -- Grant schema permissions
        echo GRANT ALL ON SCHEMA public TO securevault;
        echo GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO securevault;
        echo GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO securevault;
        echo.
        echo -- Enable required extensions
        echo CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
        echo CREATE EXTENSION IF NOT EXISTS "pgcrypto";
        echo CREATE EXTENSION IF NOT EXISTS "pg_trgm";
    ) > init-db.sql
    echo ✅ Database initialization script created
)

REM Create monitoring directories and configuration
if not exist monitoring\prometheus mkdir monitoring\prometheus
if not exist monitoring\grafana\dashboards mkdir monitoring\grafana\dashboards
if not exist monitoring\grafana\datasources mkdir monitoring\grafana\datasources

if not exist monitoring\prometheus.yml (
    echo 📝 Creating Prometheus configuration...
    (
        echo global:
        echo   scrape_interval: 15s
        echo   evaluation_interval: 15s
        echo.
        echo rule_files:
        echo   # - "first_rules.yml"
        echo   # - "second_rules.yml"
        echo.
        echo scrape_configs:
        echo   - job_name: 'prometheus'
        echo     static_configs:
        echo       - targets: ['localhost:9090']
        echo.
        echo   - job_name: 'securevault-backend'
        echo     static_configs:
        echo       - targets: ['backend:8080']
        echo     metrics_path: '/metrics'
        echo     scrape_interval: 10s
        echo.
        echo   - job_name: 'postgres'
        echo     static_configs:
        echo       - targets: ['postgres:5432']
        echo.
        echo   - job_name: 'redis'
        echo     static_configs:
        echo       - targets: ['redis:6379']
    ) > monitoring\prometheus.yml
    echo ✅ Prometheus configuration created
)

echo.
echo 🎉 Setup completed successfully!
echo.
echo Next steps:
echo 1. Start the development environment:
echo    docker-compose up -d
echo.
echo 2. Run database migrations:
echo    cd backend ^&^& go run main.go migrate
echo.
echo 3. Start the backend server:
echo    cd backend ^&^& go run main.go
echo.
echo 4. Start the frontend:
echo    cd frontend ^&^& npm start
echo.
echo 5. Start the admin dashboard:
echo    cd admin-dashboard ^&^& npm start
echo.
echo Access URLs:
echo - Frontend: http://localhost:3000
echo - Admin Dashboard: http://localhost:3001
echo - Backend API: http://localhost:8080
echo - API Documentation: http://localhost:8080/docs
echo - Prometheus: http://localhost:9090
echo - Grafana: http://localhost:3002 (admin/admin123)
echo.
echo 🔐 Remember to change default passwords in production!
