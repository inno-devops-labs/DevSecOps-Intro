#!/usr/bin/env bash
set -euo pipefail

# DefectDojo Setup Script for Lab 10
# This script clones and starts DefectDojo locally

echo "=== DefectDojo Setup for Lab 10 ==="
echo ""

# Check prerequisites
echo "Checking prerequisites..."
command -v docker >/dev/null 2>&1 || { echo "ERROR: docker is required but not installed"; exit 1; }
command -v git >/dev/null 2>&1 || { echo "ERROR: git is required but not installed"; exit 1; }

echo "✓ Docker version: $(docker --version)"
echo "✓ Docker Compose version: $(docker compose version)"
echo ""

# Navigate to setup directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Clone DefectDojo if not already present
if [ -d "django-DefectDojo" ]; then
    echo "DefectDojo directory already exists. Skipping clone."
else
    echo "Cloning DefectDojo (shallow clone)..."
    git clone --depth 1 https://github.com/DefectDojo/django-DefectDojo.git
    echo "✓ Clone complete"
fi

cd django-DefectDojo

# Optional: Check compose compatibility
if [ -f "./docker/docker-compose-check.sh" ]; then
    echo "Running compose compatibility check..."
    ./docker/docker-compose-check.sh || echo "⚠ Compatibility check had warnings (continuing anyway)"
fi

echo ""
echo "Building DefectDojo containers (this may take 10-15 minutes on first run)..."
echo "You can monitor progress in this terminal."
echo ""

docker compose build

echo ""
echo "✓ Build complete!"
echo ""
echo "Starting DefectDojo containers..."
docker compose up -d

echo ""
echo "Waiting for containers to be healthy..."
sleep 10
docker compose ps

echo ""
echo "=== DefectDojo Setup Complete ==="
echo ""
echo "Next steps:"
echo "1. Wait 1-2 minutes for initialization to complete"
echo "2. Get admin password:"
echo "   docker compose logs initializer | grep 'Admin password:'"
echo ""
echo "3. Access the UI at: http://localhost:8080"
echo "   Username: admin"
echo "   Password: <from step 2>"
echo ""
echo "4. Get your API token from Profile → API v2 Key"
echo ""
echo "5. Run the import script with your token:"
echo "   export DD_API='http://localhost:8080/api/v2'"
echo "   export DD_TOKEN='<your_api_token>'"
echo "   bash ../imports/run-imports.sh"
echo ""
