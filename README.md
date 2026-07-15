# AVGVSTO Server

Hardware-bound encryption server with AES-256-GCM, ChaCha20-Poly1305, USB key enforcement, and audit logging.

**Live API:** `https://api.avgvstousb.com/api/v1`  
**Web App:** `https://avgvstousb.com`  
**Swagger UI:** Web App → tab **Swagger**

## Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/register` | Create account |
| POST | `/api/v1/login` | Get JWT token |
| POST | `/api/v1/refresh` | Refresh token |
| POST | `/api/v1/encrypt` | Encrypt text |
| POST | `/api/v1/decrypt` | Decrypt |
| POST | `/api/v1/verify` | Verify format |
| POST | `/api/v1/encrypt-file` | Encrypt file |
| POST | `/api/v1/decrypt-file` | Decrypt file |
| POST | `/api/v1/keys/bind-usb` | Bind USB key |
| GET | `/api/v1/keys` | List bound keys |
| GET | `/api/v1/audit-log` | Audit log (admin) |
| GET | `/api/v1/health` | Server status |
| GET | `/api/v1/openapi.json` | OpenAPI spec |

## Quick Start (Python)

```python
import requests

API = 'https://api.avgvstousb.com/api/v1'

# Register
r = requests.post(f'{API}/register', json={'username': 'user', 'password': 'pass'})
print(r.json())

# Login
r = requests.post(f'{API}/login', json={'username': 'user', 'password': 'pass'})
token = r.json()['access_token']
headers = {'Authorization': f'Bearer {token}'}

# Encrypt with passphrase
r = requests.post(f'{API}/encrypt', json={
    'data': 'Hello World',
    'passphrase': 'mypassphrase'
}, headers=headers)
print(r.json())

# Decrypt
enc = r.json()['encrypted_data']
r = requests.post(f'{API}/decrypt', json={
    'encrypted_data': enc,
    'passphrase': 'mypassphrase'
}, headers=headers)
print(r.json())
```

## Tech Stack

- **Backend:** Rust (Axum, SQLx, utoipa)
- **Database:** PostgreSQL (Neon.tech)
- **Deployment:** Fly.io, Cloudflare (DNS + Pages)
- **Crypto:** AES-256-GCM, ChaCha20-Poly1305, PBKDF2-HMAC-SHA256
- **Auth:** JWT (access + refresh tokens), USB hardware fingerprint

## Architecture

```
avgvsto-server/          Main server binary
avgvsto-core/            Core crypto logic
avgvsto-auth/            Authentication & JWT
avgvsto-audit/           Audit logging
```

## Development

```bash
# Run locally
cp config/default.toml config/development.toml
cargo run --package avgvsto-server
```

## License

GPLv3 — see [LICENSE](LICENSE).
