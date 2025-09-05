# SecureVault API Documentation

## Overview

SecureVault provides a comprehensive REST API for secure password management with enterprise-grade security features.

## Base URL

```
https://api.securevault.com/v1
```

Development: `http://localhost:8080/api/v1`

## Authentication

All API requests require authentication using JWT Bearer tokens.

### Headers

```http
Authorization: Bearer <jwt_token>
Content-Type: application/json
X-API-Version: v1
```

### Rate Limiting

- **Standard Users**: 100 requests per minute
- **Premium Users**: 500 requests per minute  
- **Admin Users**: 1000 requests per minute

Rate limit headers are included in responses:

```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1640995200
```

## Endpoints

### Authentication

#### POST /auth/register

Register a new user account.

**Request:**
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "first_name": "John",
  "last_name": "Doe"
}
```

**Response:**
```json
{
  "user": {
    "id": "123e4567-e89b-12d3-a456-426614174000",
    "email": "user@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "role": "basic_user",
    "status": "pending",
    "created_at": "2023-01-01T00:00:00Z"
  },
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 900
}
```

#### POST /auth/login

Authenticate and obtain access tokens.

**Request:**
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "mfa_token": "123456",
  "device_info": {
    "browser": "Chrome",
    "os": "Windows",
    "device_type": "desktop",
    "fingerprint": "abc123def456"
  }
}
```

**Response:**
```json
{
  "user": {
    "id": "123e4567-e89b-12d3-a456-426614174000",
    "email": "user@example.com",
    "role": "premium_user",
    "mfa_enabled": true
  },
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 900
}
```

#### POST /auth/refresh

Refresh access token using refresh token.

#### POST /auth/logout

Revoke current session.

### Multi-Factor Authentication

#### POST /mfa/totp/setup

Setup TOTP authenticator.

**Response:**
```json
{
  "secret": "JBSWY3DPEHPK3PXP",
  "qr_code": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA...",
  "url": "otpauth://totp/SecureVault:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=SecureVault",
  "backup_codes": [
    "12345-67890",
    "09876-54321"
  ]
}
```

#### POST /mfa/totp/verify

Verify TOTP token.

#### POST /mfa/webauthn/begin-registration

Begin WebAuthn registration.

#### POST /mfa/webauthn/finish-registration

Complete WebAuthn registration.

### Vault Items

#### GET /vault/items

Retrieve user's vault items.

**Query Parameters:**
- `type`: Filter by item type (password, secure_note, credit_card, etc.)
- `folder_id`: Filter by folder
- `search`: Search term
- `limit`: Number of items (default: 50, max: 100)
- `offset`: Pagination offset

**Response:**
```json
{
  "items": [
    {
      "id": "123e4567-e89b-12d3-a456-426614174000",
      "type": "password",
      "name": "Gmail Account",
      "data": {
        "data": "encrypted_content_here",
        "nonce": "random_nonce",
        "algorithm": "AES-256-GCM",
        "key_id": "item_key_123",
        "timestamp": "2023-01-01T00:00:00Z"
      },
      "tags": ["email", "personal"],
      "favorite": false,
      "last_used": "2023-01-01T12:00:00Z",
      "created_at": "2023-01-01T00:00:00Z",
      "updated_at": "2023-01-01T00:00:00Z"
    }
  ],
  "total": 25,
  "limit": 50,
  "offset": 0
}
```

#### POST /vault/items

Create a new vault item.

**Request:**
```json
{
  "type": "password",
  "name": "GitHub Account",
  "data": {
    "username": "john_doe",
    "password": "SuperSecretPassword123!",
    "url": "https://github.com",
    "notes": "Work account"
  },
  "folder_id": "456e7890-e89b-12d3-a456-426614174000",
  "tags": ["work", "development"]
}
```

#### GET /vault/items/{id}

Retrieve a specific vault item.

#### PUT /vault/items/{id}

Update a vault item.

#### DELETE /vault/items/{id}

Delete a vault item.

#### POST /vault/items/{id}/share

Share a vault item with another user.

**Request:**
```json
{
  "user_email": "colleague@example.com",
  "permissions": {
    "read": true,
    "write": false,
    "delete": false,
    "share": false
  },
  "expires_at": "2023-12-31T23:59:59Z"
}
```

### Folders

#### GET /vault/folders

Get user's folders.

#### POST /vault/folders

Create a new folder.

#### PUT /vault/folders/{id}

Update a folder.

#### DELETE /vault/folders/{id}

Delete a folder.

### Search

#### GET /search

Search vault items.

**Query Parameters:**
- `q`: Search query
- `type`: Item type filter
- `tags`: Tag filter (comma-separated)

### User Profile

#### GET /auth/profile

Get current user profile.

#### PUT /auth/profile

Update user profile.

#### POST /auth/change-password

Change user password.

### Admin Endpoints

#### GET /admin/users

Get all users (Admin only).

#### POST /admin/users

Create a new user (Admin only).

#### PUT /admin/users/{id}

Update user (Admin only).

#### DELETE /admin/users/{id}

Delete user (Admin only).

#### GET /admin/audit/logs

Get audit logs (Admin only).

#### GET /admin/system/health

Get system health status (Admin only).

## Error Handling

API uses standard HTTP status codes:

- `200` - Success
- `201` - Created
- `400` - Bad Request
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Not Found
- `429` - Too Many Requests
- `500` - Internal Server Error

**Error Response Format:**
```json
{
  "error": {
    "code": "INVALID_CREDENTIALS",
    "message": "Invalid email or password",
    "details": {
      "field": "password",
      "reason": "Password verification failed"
    },
    "timestamp": "2023-01-01T00:00:00Z",
    "request_id": "req_123456789"
  }
}
```

## Data Types

### Vault Item Types

- `password` - Username/password combinations
- `secure_note` - Encrypted text notes
- `credit_card` - Payment card information
- `identity` - Personal identification documents
- `crypto_key` - API keys, SSH keys, certificates
- `file` - Encrypted file storage

### User Roles

- `basic_user` - Standard user (max 100 items)
- `premium_user` - Premium features (unlimited items)
- `team_member` - Team collaboration access
- `vault_admin` - User management
- `security_admin` - Security configuration
- `super_admin` - Full system access

## SDKs

Official SDKs available for:

- JavaScript/TypeScript
- Python
- Go
- Java
- C#
- PHP

## Webhooks

Configure webhooks to receive real-time notifications:

```json
{
  "url": "https://your-app.com/webhooks/securevault",
  "events": [
    "item.created",
    "item.updated", 
    "item.deleted",
    "user.login",
    "security.incident"
  ],
  "secret": "webhook_secret_key"
}
```

## Examples

### Complete Login Flow

```javascript
// 1. Login
const loginResponse = await fetch('/api/v1/auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    email: 'user@example.com',
    password: 'password123',
    device_info: {
      browser: 'Chrome',
      os: 'Windows',
      device_type: 'desktop'
    }
  })
});

const loginData = await loginResponse.json();

// 2. If MFA required
if (loginData.mfa_required) {
  const mfaResponse = await fetch('/api/v1/auth/verify-mfa', {
    method: 'POST',
    headers: { 
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${loginData.access_token}`
    },
    body: JSON.stringify({
      token: '123456',
      type: 'totp'
    })
  });
}

// 3. Access protected resources
const vaultResponse = await fetch('/api/v1/vault/items', {
  headers: {
    'Authorization': `Bearer ${loginData.access_token}`
  }
});
```

### Create Encrypted Vault Item

```javascript
// Client-side encryption before sending
import CryptoJS from 'crypto-js';

const itemData = {
  username: 'john_doe',
  password: 'secret123',
  url: 'https://example.com'
};

// Generate item-specific encryption key
const itemKey = CryptoJS.lib.WordArray.random(256/8);
const nonce = CryptoJS.lib.WordArray.random(96/8);

// Encrypt data
const encrypted = CryptoJS.AES.encrypt(
  JSON.stringify(itemData),
  itemKey,
  { 
    mode: CryptoJS.mode.GCM,
    iv: nonce
  }
);

// Send to API
const response = await fetch('/api/v1/vault/items', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${accessToken}`
  },
  body: JSON.stringify({
    type: 'password',
    name: 'Example Account',
    data: {
      data: encrypted.toString(),
      nonce: nonce.toString(),
      algorithm: 'AES-256-GCM',
      key_id: generateItemKeyId()
    }
  })
});
```

## Security

### Encryption

- **Data at Rest**: AES-256-GCM
- **Data in Transit**: TLS 1.3
- **Key Management**: PBKDF2 with 100,000+ iterations
- **Zero-Knowledge**: Server never sees plaintext data

### Authentication

- **JWT Tokens**: 15-minute expiry
- **Refresh Tokens**: 7-day expiry
- **MFA Support**: TOTP, WebAuthn, SMS
- **Session Management**: Device fingerprinting

### Rate Limiting

- **Sliding Window**: 1-minute intervals
- **Progressive Penalties**: Increasing delays
- **IP-based Limits**: Per-IP restrictions
- **User-based Limits**: Per-user quotas

## Support

- **Documentation**: https://docs.securevault.com
- **Status Page**: https://status.securevault.com
- **Support**: support@securevault.com
- **Security Issues**: security@securevault.com
