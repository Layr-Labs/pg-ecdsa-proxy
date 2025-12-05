#!/bin/bash
set -e

# Generate random credentials for internal Postgres
# These are never exposed - only the proxy knows them
generate_random() {
    head -c 32 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c "$1"
}

# Only generate if not explicitly set (allows override for debugging)
if [ -z "$PG_RANDOM_CREDS" ] || [ "$PG_RANDOM_CREDS" = "true" ]; then
    RANDOM_USER="svc_$(generate_random 12)"
    RANDOM_PASS="$(generate_random 32)"
    
    # Set for Postgres initialization
    export POSTGRES_USER="$RANDOM_USER"
    export POSTGRES_PASSWORD="$RANDOM_PASS"
    export POSTGRES_DB="${POSTGRES_DB:-postgres}"
    
    # Set for proxy connection
    export PG_USER="$RANDOM_USER"
    export PG_PASSWORD="$RANDOM_PASS"
    export PG_DATABASE="${PG_DATABASE:-$POSTGRES_DB}"
    
    echo "Generated random internal credentials (user: $RANDOM_USER)"
fi

# Start Postgres in the background using the official entrypoint
echo "Starting PostgreSQL..."
docker-entrypoint.sh postgres &
PG_PID=$!

# Wait for Postgres to be ready
echo "Waiting for PostgreSQL to be ready..."
until pg_isready -h localhost -U "$POSTGRES_USER" -d "$POSTGRES_DB" > /dev/null 2>&1; do
    sleep 1
done
echo "PostgreSQL is ready!"

# Start the proxy
echo "Starting ECDSA Proxy..."
exec /usr/local/bin/proxy &
PROXY_PID=$!

# Handle shutdown
shutdown() {
    echo "Shutting down..."
    kill $PROXY_PID 2>/dev/null || true
    kill $PG_PID 2>/dev/null || true
    wait
    exit 0
}

trap shutdown SIGTERM SIGINT

# Wait for either process to exit
wait -n $PG_PID $PROXY_PID

# If we get here, one process died - shut down the other
shutdown

