# rust-sso

A lightweight SSO authentication service built with Rust, featuring Cloudflare Access integration.

## Features

- **OIDC Provider** - Full OpenID Connect support (JWKS, Token, UserInfo, Discovery)
- **Email + Password** authentication with bcrypt hashing
- **Email verification codes** for 2FA (6-digit codes, 5-minute expiry)
- **Cloudflare Access** integration (validate CF Access JWTs)
- **SQLite** database (zero-config, single binary deployment)
- **JWT** with RS256 signing and JWKS endpoint

## Quick Start

```bash
# 1. Clone and build
git clone https://github.com/h382110229/rust-sso.git
cd rust-sso
cargo build --release

# 2. Configure
cp .env.example .env
# Edit .env with your settings

# 3. Run
./target/release/rust-sso
```

## API Endpoints

### Authentication
- `POST /api/v1/auth/register` - Register with email + password
- `POST /api/v1/auth/login` - Login and get JWT
- `POST /api/v1/auth/refresh` - Refresh token
- `POST /api/v1/auth/logout` - Revoke session

### OIDC
- `GET /.well-known/openid-configuration` - OIDC Discovery
- `GET /api/v1/oidc/jwks` - JWKS endpoint
- `POST /api/v1/oidc/token` - Token endpoint
- `GET /api/v1/oidc/userinfo` - UserInfo endpoint

### Users
- `GET /api/v1/users/me` - Get current user profile
- `PUT /api/v1/users/me/password` - Change password

### Health
- `GET /health` - Health check

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `APP__SERVER__PORT` | Server port | 8080 |
| `APP__DATABASE__URL` | SQLite database URL | sqlite:rust-sso.db |
| `APP__JWT__SECRET` | JWT secret key | (required) |
| `APP__JWT__EXPIRY` | Token expiry in seconds | 3600 |
| `SMTP_HOST` | SMTP server host | (required for email) |
| `SMTP_PORT` | SMTP server port | 587 |
| `SMTP_USERNAME` | SMTP username | (required for email) |
| `SMTP_PASSWORD` | SMTP password | (required for email) |
| `SMTP_FROM` | Sender email address | (required for email) |
| `CF_ACCESS_TEAM` | Cloudflare Access team domain | (optional) |

## Integration with Your Projects

### As an OIDC Provider

```javascript
// Example: OIDC login with rust-sso
const response = await fetch('https://sso.example.com/api/v1/oidc/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    grant_type: 'password',
    username: 'user@example.com',
    password: 'password',
    client_id: 'your-client-id'
  })
});
const { access_token } = await response.json();
```

### Validate JWT

```javascript
// Fetch JWKS from rust-sso
const jwks = await fetch('https://sso.example.com/.well-known/jwks.json').then(r => r.json());
// Use any JWT library to verify with the JWKS
```

### Cloudflare Access Integration

When `CF_ACCESS_TEAM` is set, rust-sso can validate CF Access JWTs:

```bash
# Protected service receives CF Access header
# rust-sso validates it and returns user info
curl -H "Cf-Access-Jwt-Assertion: <token>" https://sso.example.com/api/v1/oidc/userinfo
```

## Tech Stack

- **Axum** - Web framework
- **SQLx** - Async SQLite driver
- **jsonwebtoken** - JWT signing/verification
- **bcrypt** - Password hashing
- **lettre** - SMTP email
- **reqwest** - HTTP client (for CF Access JWKS)

## License

MIT
