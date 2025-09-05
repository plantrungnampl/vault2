# SecureVault - Enterprise-Grade Password Management System

## Overview
A production-ready, military-grade secure vault system with comprehensive access control, zero-knowledge encryption, and complete separation between user and admin roles.

## Architecture

```
┌─────────────────────┐    ┌─────────────────────┐
│   Desktop Client    │    │   Admin Web App     │
│  (Tauri + React)    │    │    (React PWA)      │
│                     │    │                     │
│ • Vault CRUD        │    │ • User Management   │
│ • AES-256-GCM       │    │ • Security Policies │
│ • MFA/TOTP/FIDO2    │    │ • Audit Logs        │
│ • Offline-first     │    └─────────────────────┘
│ • Local DB (SQLite) │
└──────────┬──────────┘
           │ HTTPS/TLS 1.3
           ▼
┌─────────────────────────────────┐
│        Backend Server           │
│             (Go)                │
│                                 │
│ • User accounts & RBAC          │
│ • MFA enforcement               │
│ • JWT/Refresh Tokens            │
│ • Sync encrypted vault items    │
│ • Audit logging (JSON)          │
│ • Key rotation management       │
└─────────────┬───────────────────┘
              │
              ▼
┌─────────────────────────────────┐
│           Database              │
│         PostgreSQL              │
│ • Encrypted at rest             │
│ • JSONB for vault items         │
│ • Trigram index for search      │
└─────────────┬───────────────────┘
              │
              ▼
┌─────────────────────────────────┐
│             Cache               │
│            Redis                │
│ • Session store                 │
│ • Rate limiting                 │
│ • MFA token cache               │
└─────────────────────────────────┘
```

## Security Features

### 🔒 Zero-Knowledge Architecture
- Client-side encryption/decryption only
- Server never accesses plaintext data
- AES-256-GCM encryption for all vault items
- Separate encryption keys per item

### 🛡️ Multi-Factor Authentication
- TOTP (RFC 6238)
- FIDO2/WebAuthn
- Biometric authentication simulation
- SMS backup codes
- Hardware token support

### 👥 Role-Based Access Control
- **User Roles**: Basic, Premium, Team Member
- **Admin Roles**: Vault Admin, Security Admin, Super Admin
- Complete separation of user and admin interfaces

### 📊 Comprehensive Audit Logging
- Tamper-proof blockchain-style hash chaining
- Real-time security monitoring
- 5-year retention with encrypted storage

## Quick Start

### Prerequisites
- Go 1.21+
- Node.js 18+
- PostgreSQL 15+
- Redis 7+
- Docker & Docker Compose

### Development Setup

1. **Clone and setup**
```bash
git clone <repository>
cd vault_dev
chmod +x scripts/setup.sh
./scripts/setup.sh
```

2. **Start development environment**
```bash
docker-compose up -d
cd backend && go run main.go
cd frontend && npm start
cd admin-dashboard && npm start
```

3. **Access the applications**
- User Interface: http://localhost:3000
- Admin Dashboard: http://localhost:3001
- API Documentation: http://localhost:8080/docs

### Production Deployment

```bash
# Build and deploy
docker-compose -f docker-compose.prod.yml up -d

# Or use Kubernetes
kubectl apply -f k8s/
```

## Security Standards Compliance

- ✅ OWASP Top 10 Protection
- ✅ NIST Cybersecurity Framework
- ✅ ISO 27001, 27017, 27018
- ✅ GDPR & CCPA Compliant
- ✅ SOC 2 Type II Ready
- ✅ HIPAA Compliant Data Handling

## Testing

```bash
# Run all tests
make test

# Security tests
make test-security

# Performance tests
make test-performance

# Coverage report
make coverage
```

## API Documentation

- **OpenAPI Spec**: `/docs/api.yaml`
- **Postman Collection**: `/docs/SecureVault.postman_collection.json`
- **Interactive Docs**: http://localhost:8080/docs

## Monitoring & Alerting

- **Health Checks**: `/health`, `/ready`
- **Metrics**: Prometheus format at `/metrics`
- **Logs**: Structured JSON logging
- **Alerts**: Grafana dashboards included

## Support

- 📖 **Documentation**: `/docs/`
- 🐛 **Issues**: GitHub Issues
- 💬 **Discussions**: GitHub Discussions
- 📧 **Security**: security@securevault.com

## License

Enterprise License - See [LICENSE](LICENSE) for details.

---

**Security Notice**: This system implements military-grade security. Always follow the security checklist before deployment and conduct regular security audits.
