# PostgresECDSAAuth

A PostgreSQL proxy that authenticates users via ECDSA signatures (Ethereum-style).

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
echo "ALLOWED_ADDRESS=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266" > .env

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

## Configuration

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| `ALLOWED_ADDRESS` | Ethereum address allowed to connect | - |
| `PG_HOST` | PostgreSQL host | `postgres` |
| `PG_PORT` | PostgreSQL port | `5432` |
| `PG_USER` | Service account user | `postgres` |
| `PG_PASSWORD` | Service account password | `postgres` |

## Security Notes

- Signatures are valid for 5 minutes (configurable in `auth.py`)
- V1 only supports a single hardcoded address
- Production: Use TLS termination in front of the proxy
