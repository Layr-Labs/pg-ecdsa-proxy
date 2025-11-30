# pg-ecdsa-proxy

A high-performance PostgreSQL proxy that authenticates users via ECDSA signatures (Ethereum-style). Written in Rust.

## How it works

```
┌─────────┐     sign challenge      ┌─────────────┐     service acct     ┌──────────┐
│  Client │ ◄─────────────────────► │ Auth Proxy  │ ◄──────────────────► │ Postgres │
└─────────┘   verify signature      └─────────────┘                      └──────────┘
```

1. Client connects using their Ethereum address as `user`
2. Client provides `password` in format: `<timestamp>:<signature>`
3. Proxy verifies the signature matches the claimed address
4. If valid, proxy connects to Postgres with service account and proxies queries

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
# Edit .env with your settings:
#   ALLOWED_ADDRESS=0x...  (Ethereum address allowed to connect)
#   PG_HOST=...            (Your Postgres host)
#   PG_USER=...            (Service account)
#   PG_PASSWORD=...        (Service account password)

# Deploy to TEE
eigenx app deploy
```

### Monitor

```bash
# View app status
eigenx app info

# View logs
eigenx app logs --watch

# List all apps
eigenx app list
```

### Enable TLS (Production)

```bash
# Add TLS configuration
eigenx app configure tls

# Add TLS variables to .env
cat .env.example.tls >> .env
# Set DOMAIN=yourdomain.com and APP_PORT=5433

# Deploy with TLS
eigenx app upgrade
```

Then create a DNS A record pointing your domain to the instance IP (from `eigenx app info`).

### Manage

```bash
eigenx app stop pg-ecdsa-proxy    # Stop
eigenx app start pg-ecdsa-proxy   # Start
eigenx app terminate pg-ecdsa-proxy  # Remove
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

## License

MIT
