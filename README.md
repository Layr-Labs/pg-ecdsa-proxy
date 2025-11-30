# pg-ecdsa-proxy

A high-performance PostgreSQL proxy that authenticates users via ECDSA signatures (Ethereum-style). Written in Rust.

## Features

- **ECDSA Authentication** - Users authenticate with Ethereum signatures instead of passwords
- **Encrypted Backups** - Automatic encrypted backups to S3-compatible storage (AWS S3, Cloudflare R2, MinIO)
- **TEE-Ready** - Designed for deployment in Trusted Execution Environments with EigenCompute

## How it works

```
┌─────────┐     sign challenge      ┌─────────────┐     service acct     ┌──────────┐
│  Client │ ◄─────────────────────► │ Auth Proxy  │ ◄──────────────────► │ Postgres │
└─────────┘   verify signature      └─────────────┘                      └──────────┘
                                           │
                                           ▼
                                    ┌─────────────┐
                                    │  Encrypted  │
                                    │   Backups   │
                                    │  (S3/R2)    │
                                    └─────────────┘
```

1. Client connects using their Ethereum address as `user`
2. Client provides `password` in format: `<timestamp>:<signature>`
3. Proxy verifies the signature matches the claimed address
4. If valid, proxy connects to Postgres with service account and proxies queries
5. Periodic encrypted backups are uploaded to S3-compatible storage

## Quick Start (Local)

```bash
# Set your allowed Ethereum address
export ALLOWED_ADDRESS=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266

# Start services
docker compose up -d

# Test with TypeScript client
cd example
npm install
PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 npm start
```

## Deploy to EigenCompute (TEE)

Deploy the proxy to a Trusted Execution Environment with [EigenX CLI](https://github.com/Layr-Labs/eigenx-cli).

### Prerequisites

```bash
# Install eigenx CLI
curl -fsSL https://eigenx-scripts.s3.us-east-1.amazonaws.com/install-eigenx.sh | bash

# Authenticate
eigenx auth login  # or: eigenx auth generate --store

# Ensure you have Sepolia ETH for deployment transactions
eigenx auth whoami
```

### Deploy

```bash
# Clone the repo
git clone https://github.com/Layr-Labs/pg-ecdsa-proxy.git
cd pg-ecdsa-proxy

# Configure environment
cp .env.example .env
# Edit .env with your settings

# Deploy to TEE
eigenx app deploy
```

### Monitor

```bash
eigenx app info
eigenx app logs --watch
```

### Enable TLS (Production)

```bash
eigenx app configure tls
cat .env.example.tls >> .env
# Set DOMAIN=yourdomain.com
eigenx app upgrade
```

## Encrypted Backups

Backups are encrypted using a key derived from the `MNEMONIC` environment variable (automatically provided by EigenCompute TEE). Only the TEE instance can decrypt its own backups.

### Automatic Restore on Startup

When the proxy starts, it automatically:
1. Checks if the database is empty (no user tables)
2. If empty, downloads the latest encrypted backup from S3
3. Decrypts and restores the backup

This ensures seamless recovery when redeploying or migrating TEE instances.

### Backup Configuration

Add these to your `.env`:

```bash
# S3-compatible storage (works with AWS S3, Cloudflare R2, MinIO, etc.)
BACKUP_S3_ENDPOINT=https://your-account-id.r2.cloudflarestorage.com
BACKUP_S3_BUCKET=pg-backups
BACKUP_S3_ACCESS_KEY=your_access_key
BACKUP_S3_SECRET_KEY=your_secret_key
BACKUP_S3_REGION=auto

# Backup settings
BACKUP_PREFIX=my-app                    # Backup folder prefix
BACKUP_INTERVAL_SECS=86400              # Backup every 24 hours (default)
BACKUP_RETENTION_COUNT=7                # Keep last 7 backups (optional)
BACKUP_RETENTION_DAYS=30                # Or delete backups older than 30 days (optional)

# Encryption (provided automatically by EigenCompute)
MNEMONIC=your twelve word mnemonic phrase here
```

### Storage Providers

#### Cloudflare R2

```bash
BACKUP_S3_ENDPOINT=https://<account-id>.r2.cloudflarestorage.com
BACKUP_S3_REGION=auto
```

Get credentials from Cloudflare Dashboard → R2 → Manage R2 API Tokens.

#### AWS S3

```bash
BACKUP_S3_ENDPOINT=https://s3.us-east-1.amazonaws.com
BACKUP_S3_REGION=us-east-1
```

#### MinIO (Self-hosted)

```bash
BACKUP_S3_ENDPOINT=https://minio.example.com
BACKUP_S3_REGION=us-east-1
```

### Encryption Details

- **Algorithm**: AES-256-GCM (authenticated encryption)
- **Key Derivation**: HKDF-SHA256 from MNEMONIC
- **Nonce**: Random 12 bytes prepended to each backup
- **Format**: `[12-byte nonce][ciphertext][16-byte auth tag]`

Only the TEE instance with the same MNEMONIC can decrypt backups. This ensures:
- Backups are useless if storage is compromised
- Only your TEE can restore from backups
- No external key management needed

### Restore from Backup

**Automatic**: The proxy automatically restores from the latest backup when the database is empty on startup. Just deploy with the same MNEMONIC.

**Manual**: To manually restore, download and decrypt the backup:

```bash
# Download encrypted backup
aws s3 cp s3://pg-backups/my-app/20240101_120000.backup.enc ./backup.enc

# Decrypt using the same MNEMONIC (requires implementing decryption tool)
# Key derivation: HKDF-SHA256(salt="pg-ecdsa-proxy-backup", ikm=MNEMONIC, info="backup-encryption-key")
# Encryption: AES-256-GCM, first 12 bytes are nonce

# Restore to Postgres
pg_restore -h localhost -U postgres -d mydb ./backup.dump
```

## Client Integration

### TypeScript (with postgres.js)

```typescript
import postgres from "postgres";
import { privateKeyToAccount } from "viem/accounts";

const account = privateKeyToAccount(PRIVATE_KEY);
const timestamp = Math.floor(Date.now() / 1000).toString();
const signature = await account.signMessage({ message: timestamp });

const sql = postgres({
  host: "localhost",
  port: 5434,
  user: account.address,
  password: `${timestamp}:${signature}`,
  database: "postgres",
});

const result = await sql`SELECT * FROM users`;
```

### Python (with psycopg2)

```python
import time
import psycopg2
from eth_account import Account
from eth_account.messages import encode_defunct

account = Account.from_key(PRIVATE_KEY)
timestamp = str(int(time.time()))
sig = account.sign_message(encode_defunct(text=timestamp))

conn = psycopg2.connect(
    host="localhost",
    port=5434,
    user=account.address,
    password=f"{timestamp}:{sig.signature.hex()}",
    dbname="postgres"
)
```

### Rust (with tokio-postgres)

```rust
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use tokio_postgres::NoTls;

let signer: PrivateKeySigner = PRIVATE_KEY.parse().unwrap();
let timestamp = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH).unwrap()
    .as_secs().to_string();
let sig = signer.sign_message_sync(timestamp.as_bytes()).unwrap();
let password = format!("{}:0x{}", timestamp, hex::encode(sig.as_bytes()));

let (client, connection) = tokio_postgres::connect(
    &format!(
        "host=localhost port=5434 user={} password={} dbname=postgres",
        signer.address(), password
    ),
    NoTls,
).await?;
```

## Configuration

### Proxy Settings

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| `ALLOWED_ADDRESS` | Ethereum address allowed to connect | - |
| `PROXY_HOST` | Proxy listen address | `0.0.0.0` |
| `PROXY_PORT` | Proxy listen port | `5433` |
| `PG_HOST` | PostgreSQL host | `postgres` |
| `PG_PORT` | PostgreSQL port | `5432` |
| `PG_USER` | Service account user | `postgres` |
| `PG_PASSWORD` | Service account password | `postgres` |
| `SIGNATURE_WINDOW_SECS` | Signature validity window | `300` (5 min) |

### Backup Settings

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| `BACKUP_S3_ENDPOINT` | S3-compatible endpoint URL | - (disabled) |
| `BACKUP_S3_BUCKET` | Bucket name | - |
| `BACKUP_S3_ACCESS_KEY` | Access key ID | - |
| `BACKUP_S3_SECRET_KEY` | Secret access key | - |
| `BACKUP_S3_REGION` | Region | `auto` |
| `BACKUP_PREFIX` | Backup path prefix | `pg-backup` |
| `BACKUP_INTERVAL_SECS` | Backup interval | `86400` (24h) |
| `BACKUP_RETENTION_COUNT` | Keep last N backups | - (keep all) |
| `BACKUP_RETENTION_DAYS` | Delete backups older than N days | - (keep all) |
| `MNEMONIC` | Encryption key source (from TEE) | - (unencrypted) |

## Building

```bash
# Build locally
cargo build --release

# Build Docker image
docker build -t pg-ecdsa-proxy .
```

## Security Notes

- Signatures are valid for 5 minutes (configurable via `SIGNATURE_WINDOW_SECS`)
- V1 only supports a single allowed address
- Production: Use TLS termination in front of the proxy
- EigenCompute deployment runs in Intel TDX secure enclave with hardware isolation
- Backups are encrypted with MNEMONIC-derived key (only TEE can decrypt)

## License

MIT
