# SecureVault - Enterprise Password Manager
# Makefile for development and deployment

.PHONY: help setup dev build test clean docker k8s security-check

# Default target
help:
	@echo "🔐 SecureVault - Enterprise Password Manager"
	@echo "==========================================="
	@echo ""
	@echo "Available targets:"
	@echo "  setup          - Initial project setup"
	@echo "  dev            - Start development environment"
	@echo "  build          - Build all components"
	@echo "  test           - Run all tests"
	@echo "  test-security  - Run security tests"
	@echo "  test-coverage  - Generate test coverage reports"
	@echo "  clean          - Clean build artifacts"
	@echo "  docker         - Build and start Docker containers"
	@echo "  docker-prod    - Build production Docker images"
	@echo "  k8s            - Deploy to Kubernetes"
	@echo "  security-check - Run security analysis"
	@echo "  lint           - Run linters"
	@echo "  format         - Format code"
	@echo "  docs           - Generate documentation"
	@echo "  backup         - Create system backup"
	@echo "  restore        - Restore from backup"

# Project setup
setup:
	@echo "🔧 Setting up SecureVault development environment..."
	@chmod +x scripts/setup.sh
	@./scripts/setup.sh

# Development
dev:
	@echo "🚀 Starting development environment..."
	@docker-compose up -d postgres redis elasticsearch prometheus grafana
	@echo "✅ Infrastructure started"
	@echo "📚 Starting services..."
	@$(MAKE) -j4 dev-backend dev-frontend dev-admin dev-desktop

dev-backend:
	@echo "🔧 Starting backend..."
	@cd backend && go run main.go

dev-frontend:
	@echo "🎨 Starting frontend (Vite)..."
	@cd frontend && npm run dev

dev-admin:
	@echo "⚙️ Starting admin dashboard (Vite)..."
	@cd admin-dashboard && npm run dev

dev-desktop:
	@echo "🖥️ Starting desktop client (Tauri)..."
	@cd desktop-client && npm run tauri dev

# Build
build: build-backend build-frontend build-admin build-desktop

build-backend:
	@echo "🔨 Building backend..."
	@cd backend && go build -o bin/securevault-backend main.go

build-frontend:
	@echo "🔨 Building frontend (Vite)..."
	@cd frontend && npm run build

build-admin:
	@echo "🔨 Building admin dashboard (Vite)..."
	@cd admin-dashboard && npm run build

build-desktop:
	@echo "🔨 Building desktop client (Tauri)..."
	@cd desktop-client && npm run tauri build

# Testing
test: test-backend test-frontend test-admin test-desktop test-integration

test-backend:
	@echo "🧪 Running backend tests..."
	@cd backend && go test -v ./...

test-frontend:
	@echo "🧪 Running frontend tests (Vitest)..."
	@cd frontend && npm run test

test-admin:
	@echo "🧪 Running admin dashboard tests (Vitest)..."
	@cd admin-dashboard && npm run test

test-desktop:
	@echo "🧪 Running desktop client tests..."
	@cd desktop-client && npm run test

test-integration:
	@echo "🧪 Running integration tests..."
	@cd tests && go test -v ./...

test-security:
	@echo "🔒 Running security tests..."
	@cd backend && go test -v ./internal/security/...
	@cd frontend && npm audit --audit-level moderate
	@cd admin-dashboard && npm audit --audit-level moderate
	@cd desktop-client && npm audit --audit-level moderate

test-coverage:
	@echo "📊 Generating test coverage reports..."
	@cd backend && go test -coverprofile=coverage.out ./... && go tool cover -html=coverage.out -o coverage.html
	@cd frontend && npm run test:coverage
	@cd admin-dashboard && npm run test:coverage

# Security
security-check:
	@echo "🛡️ Running security analysis..."
	@gosec ./backend/...
	@cd frontend && npm audit --audit-level high
	@cd admin-dashboard && npm audit --audit-level high
	@docker run --rm -v $(PWD):/app -w /app securecodewarrior/docker-superlinter

# Code quality
lint: lint-backend lint-frontend lint-admin

lint-backend:
	@echo "🔍 Linting backend..."
	@cd backend && golangci-lint run

lint-frontend:
	@echo "🔍 Linting frontend..."
	@cd frontend && npm run lint

lint-admin:
	@echo "🔍 Linting admin dashboard..."
	@cd admin-dashboard && npm run lint

format: format-backend format-frontend format-admin

format-backend:
	@echo "✨ Formatting backend..."
	@cd backend && go fmt ./...
	@cd backend && goimports -w .

format-frontend:
	@echo "✨ Formatting frontend..."
	@cd frontend && npm run lint:fix

format-admin:
	@echo "✨ Formatting admin dashboard..."
	@cd admin-dashboard && npm run lint:fix

# Docker
docker:
	@echo "🐳 Building and starting Docker containers..."
	@docker-compose up --build -d

docker-prod:
	@echo "🐳 Building production Docker images..."
	@docker build -t securevault/backend:latest ./backend
	@docker build -t securevault/frontend:latest ./frontend
	@docker build -t securevault/admin-dashboard:latest ./admin-dashboard

docker-stop:
	@echo "🛑 Stopping Docker containers..."
	@docker-compose down

docker-clean:
	@echo "🧹 Cleaning Docker resources..."
	@docker-compose down -v --rmi all --remove-orphans

# Kubernetes
k8s:
	@echo "☸️ Deploying to Kubernetes..."
	@kubectl apply -f k8s/

k8s-clean:
	@echo "🧹 Cleaning Kubernetes resources..."
	@kubectl delete -f k8s/

# Database
db-migrate:
	@echo "📊 Running database migrations..."
	@cd backend && go run main.go migrate

db-rollback:
	@echo "↩️ Rolling back database migration..."
	@cd backend && go run main.go migrate-down

db-seed:
	@echo "🌱 Seeding database..."
	@cd backend && go run main.go seed

db-reset:
	@echo "🔄 Resetting database..."
	@docker-compose exec postgres psql -U securevault -d securevault -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"
	@$(MAKE) db-migrate db-seed

# Backup and restore
backup:
	@echo "💾 Creating system backup..."
	@mkdir -p backups/$(shell date +%Y%m%d_%H%M%S)
	@docker-compose exec postgres pg_dump -U securevault securevault > backups/$(shell date +%Y%m%d_%H%M%S)/database.sql
	@docker-compose exec redis redis-cli --rdb backups/$(shell date +%Y%m%d_%H%M%S)/redis.rdb

restore:
	@echo "🔄 Restoring from backup..."
	@read -p "Enter backup directory name: " backup_dir; \
	docker-compose exec -T postgres psql -U securevault securevault < backups/$$backup_dir/database.sql

# Documentation
docs:
	@echo "📚 Generating documentation..."
	@cd backend && swag init -g main.go -o docs
	@cd docs && mkdocs build

docs-serve:
	@echo "📖 Serving documentation..."
	@cd docs && mkdocs serve

# Monitoring
logs:
	@echo "📋 Showing application logs..."
	@docker-compose logs -f

logs-backend:
	@docker-compose logs -f backend

logs-frontend:
	@docker-compose logs -f frontend

logs-db:
	@docker-compose logs -f postgres

monitor:
	@echo "📊 Opening monitoring dashboards..."
	@open http://localhost:9090  # Prometheus
	@open http://localhost:3002  # Grafana

# Cleanup
clean:
	@echo "🧹 Cleaning build artifacts..."
	@cd backend && rm -rf bin/ coverage.out coverage.html
	@cd frontend && rm -rf build/ coverage/
	@cd admin-dashboard && rm -rf build/ coverage/
	@rm -rf logs/*.log

clean-all: clean docker-clean
	@echo "🧹 Deep cleaning..."
	@docker system prune -f
	@go clean -cache
	@cd frontend && rm -rf node_modules/
	@cd admin-dashboard && rm -rf node_modules/

# Installation
install-deps:
	@echo "📦 Installing dependencies..."
	@cd backend && go mod download
	@cd frontend && npm install
	@cd admin-dashboard && npm install
	@cd desktop-client && npm install

install-tools:
	@echo "🔧 Installing development tools..."
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@go install github.com/securecodewarrior/scs-community-edition@latest
	@go install github.com/swaggo/swag/cmd/swag@latest
	@npm install -g prettier eslint

# Performance
benchmark:
	@echo "⚡ Running performance benchmarks..."
	@cd backend && go test -bench=. -benchmem ./...

load-test:
	@echo "🔥 Running load tests..."
	@artillery run tests/load/api-load-test.yml

# SSL/TLS
generate-certs:
	@echo "🔒 Generating SSL certificates..."
	@mkdir -p certs
	@openssl req -x509 -newkey rsa:4096 -keyout certs/server.key -out certs/server.crt -days 365 -nodes \
		-subj "/C=US/ST=CA/L=San Francisco/O=SecureVault/CN=localhost" \
		-addext "subjectAltName=DNS:localhost,DNS:*.localhost,IP:127.0.0.1"

# Version management
version:
	@echo "📌 Current version: $(shell git describe --tags --always)"

tag:
	@echo "🏷️ Creating new version tag..."
	@read -p "Enter version (e.g., v1.0.0): " version; \
	git tag -a $$version -m "Release $$version"; \
	git push origin $$version

# CI/CD
ci: test lint security-check build

deploy-staging:
	@echo "🚀 Deploying to staging..."
	@docker-compose -f docker-compose.staging.yml up -d

deploy-prod:
	@echo "🚀 Deploying to production..."
	@docker-compose -f docker-compose.prod.yml up -d

# Health checks
health:
	@echo "🏥 Checking system health..."
	@curl -f http://localhost:8080/health || echo "❌ Backend unhealthy"
	@curl -f http://localhost:3000 || echo "❌ Frontend unhealthy"
	@curl -f http://localhost:3001 || echo "❌ Admin dashboard unhealthy"

# Utilities
ssh-backend:
	@docker-compose exec backend sh

ssh-db:
	@docker-compose exec postgres psql -U securevault securevault

ssh-redis:
	@docker-compose exec redis redis-cli

ports:
	@echo "🔌 Open ports:"
	@echo "  5173 - Frontend (Vite)"
	@echo "  5174 - Admin Dashboard (Vite)"
	@echo "  3002 - Grafana"
	@echo "  5432 - PostgreSQL"
	@echo "  6379 - Redis"
	@echo "  8080 - Backend API"
	@echo "  9090 - Prometheus"
	@echo "  9200 - Elasticsearch"
	@echo "  1420 - Desktop Client (Tauri)"
