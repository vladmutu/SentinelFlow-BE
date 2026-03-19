#!/bin/bash

set -euo pipefail

echo "========================================"
echo "Starting SentinelFlow Database"
echo "========================================"

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
  echo "Error: Docker is not running. Please start Docker Desktop and try again."
  exit 1
fi

# Start the PostgreSQL container
echo "Spinning up PostgreSQL..."
docker compose up -d --remove-orphans

echo ""
echo "Database is up and running!"
echo ""
echo "How to connect via your Windows pgAdmin:"
echo "  - Host name/address: localhost"
echo "  - Port:              5433"
echo "  - Maintenance DB:    sentinel_core"
echo "  - Username:          sentinel_admin"
echo "  - Password:          supersecretpassword"
echo ""
echo "SQLAlchemy Connection String (for your .env file):"
echo "  DATABASE_URL=postgresql+asyncpg://sentinel_admin:supersecretpassword@localhost:5433/sentinel_core"
echo "========================================"
