#!/bin/bash
set -e

echo "Building Toonami Aftermath: Downlink..."
docker build -t toonami-downlink:latest .

echo ""
echo "Build complete! To run:"
echo "  docker run -d --name toonami-downlink -p 7004:7004 -v ./data:/data toonami-downlink:latest"
echo ""
echo "Or use docker-compose:"
echo "  docker-compose up -d"