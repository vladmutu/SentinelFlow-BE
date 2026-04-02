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

