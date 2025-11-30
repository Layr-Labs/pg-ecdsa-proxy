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

## Quick Start

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
use alloy_primitives::eip191_hash_message;
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

## License

MIT
