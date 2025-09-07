#!/bin/bash

# SecureVault Development Startup Script
# This script starts all development services

set -e  # Exit on any error

echo "🔐 Starting SecureVault Development Environment..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to kill all background processes on exit
cleanup() {
    echo -e "\n${YELLOW}Shutting down services...${NC}"
    kill $(jobs -p) 2>/dev/null || true
    exit
}
trap cleanup SIGINT

# Check if required tools are installed
check_dependencies() {
    echo -e "${BLUE}Checking dependencies...${NC}"
    
    if ! command -v go &> /dev/null; then
        echo -e "${RED}Go is not installed. Please install Go 1.21+${NC}"
        exit 1
    fi
    
    if ! command -v node &> /dev/null; then
        echo -e "${RED}Node.js is not installed. Please install Node.js 18+${NC}"
        exit 1
    fi
    
    if ! command -v npm &> /dev/null; then
        echo -e "${RED}npm is not installed. Please install npm${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✓ All dependencies found${NC}"
}

# Start PostgreSQL (assuming it's installed and configured)
start_database() {
    echo -e "${BLUE}Starting database...${NC}"
    
    # Check if PostgreSQL is running
    if pg_isready -q; then
        echo -e "${GREEN}✓ PostgreSQL is already running${NC}"
    else
        echo -e "${YELLOW}PostgreSQL not running. Please start PostgreSQL manually${NC}"
        echo -e "${YELLOW}Example: brew services start postgresql (macOS)${NC}"
        echo -e "${YELLOW}Example: sudo systemctl start postgresql (Linux)${NC}"
        read -p "Press Enter when PostgreSQL is running..."
    fi
}

# Start Redis (optional, for caching)
start_redis() {
    echo -e "${BLUE}Starting Redis...${NC}"
    
    if command -v redis-cli &> /dev/null && redis-cli ping &> /dev/null; then
        echo -e "${GREEN}✓ Redis is already running${NC}"
    else
        echo -e "${YELLOW}Redis not running. Starting Redis in background...${NC}"
        if command -v redis-server &> /dev/null; then
            redis-server --daemonize yes --port 6379 &
            sleep 2
            echo -e "${GREEN}✓ Redis started${NC}"
        else
            echo -e "${YELLOW}Redis not installed. Continuing without Redis...${NC}"
        fi
    fi
}

# Start backend API server
start_backend() {
    echo -e "${BLUE}Starting backend API server...${NC}"
    
    cd backend
    
    # Set environment variables
    export DATABASE_URL=${DATABASE_URL:-"postgres://postgres:password@localhost:5432/securevault?sslmode=disable"}
    export REDIS_URL=${REDIS_URL:-"redis://localhost:6379"}
    export JWT_SECRET=${JWT_SECRET:-"your-super-secret-jwt-key-change-in-production"}
    export ENCRYPTION_KEY=${ENCRYPTION_KEY:-"12345678901234567890123456789012"}
    export SERVER_PORT=${SERVER_PORT:-"8080"}
    export ENVIRONMENT=${ENVIRONMENT:-"development"}
    
    # Build and run
    echo -e "${YELLOW}Building backend...${NC}"
    go build -o securevault main.go
    
    echo -e "${GREEN}✓ Backend built successfully${NC}"
    echo -e "${YELLOW}Starting backend on port 8080...${NC}"
    
    ./securevault &
    BACKEND_PID=$!
    
    # Wait for backend to be ready
    sleep 3
    if curl -f http://localhost:8080/health > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Backend API server is running on http://localhost:8080${NC}"
    else
        echo -e "${RED}✗ Backend failed to start${NC}"
        exit 1
    fi
    
    cd ..
}

# Start frontend development server
start_frontend() {
    echo -e "${BLUE}Starting frontend development server...${NC}"
    
    cd frontend
    
    # Install dependencies if needed
    if [ ! -d "node_modules" ]; then
        echo -e "${YELLOW}Installing frontend dependencies...${NC}"
        npm install
    fi
    
    # Set environment variables
    export REACT_APP_API_URL="http://localhost:8080/api/v1"
    export PORT=3000
    
    echo -e "${YELLOW}Starting frontend on port 3000...${NC}"
    npm run dev &
    FRONTEND_PID=$!
    
    sleep 5
    echo -e "${GREEN}✓ Frontend is running on http://localhost:3000${NC}"
    
    cd ..
}

# Start admin dashboard development server
start_admin_dashboard() {
    echo -e "${BLUE}Starting admin dashboard...${NC}"
    
    cd admin-dashboard
    
    # Install dependencies if needed
    if [ ! -d "node_modules" ]; then
        echo -e "${YELLOW}Installing admin dashboard dependencies...${NC}"
        npm install
    fi
    
    # Set environment variables
    export REACT_APP_API_URL="http://localhost:8080/api/v1"
    export PORT=3001
    
    echo -e "${YELLOW}Starting admin dashboard on port 3001...${NC}"
    npm run dev &
    ADMIN_PID=$!
    
    sleep 5
    echo -e "${GREEN}✓ Admin dashboard is running on http://localhost:3001${NC}"
    
    cd ..
}

# Main execution
main() {
    echo -e "${GREEN}🔐 SecureVault Development Environment${NC}"
    echo -e "${YELLOW}======================================${NC}\n"
    
    check_dependencies
    start_database
    start_redis
    start_backend
    start_frontend
    start_admin_dashboard
    
    echo -e "\n${GREEN}🎉 All services are running!${NC}"
    echo -e "${BLUE}Services:${NC}"
    echo -e "  • Backend API:      ${GREEN}http://localhost:8080${NC}"
    echo -e "  • API Docs:         ${GREEN}http://localhost:8080/docs${NC}"
    echo -e "  • Health Check:     ${GREEN}http://localhost:8080/health${NC}"
    echo -e "  • User Frontend:    ${GREEN}http://localhost:3000${NC}"
    echo -e "  • Admin Dashboard:  ${GREEN}http://localhost:3001${NC}"
    echo -e "\n${YELLOW}Press Ctrl+C to stop all services${NC}"
    
    # Wait for user to stop
    wait
}

# Run main function
main