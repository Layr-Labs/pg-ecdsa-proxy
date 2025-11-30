#!/bin/bash
set -e

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

