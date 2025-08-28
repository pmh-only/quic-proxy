#!/bin/bash

# Start services script for Docker container
set -e

echo "Starting Coraza WAF Service..."
# Start WAF service in background
/usr/local/bin/waf-service &
WAF_PID=$!

# Wait a moment for WAF to start
sleep 2

# Check if WAF is healthy
if curl -f http://localhost:9000/health > /dev/null 2>&1; then
    echo "Coraza WAF Service started successfully (PID: $WAF_PID)"
else
    echo "Warning: Coraza WAF Service may not have started properly"
fi

echo "Starting QUIC Reverse Proxy..."
# Start the main proxy service
exec /usr/local/bin/quic-proxy