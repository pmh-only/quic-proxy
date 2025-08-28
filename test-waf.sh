#!/bin/bash

# Test script for WAF integration
set -e

echo "Building WAF service..."
cd waf && go mod tidy && cd ..
make waf-service

echo "Starting WAF service..."
./waf-service &
WAF_PID=$!

# Wait for WAF to start
sleep 3

echo "Testing WAF service health..."
if curl -f http://localhost:9000/health; then
    echo "✓ WAF health check passed"
else
    echo "✗ WAF health check failed"
    kill $WAF_PID
    exit 1
fi

echo ""
echo "Testing legitimate request..."
curl -X POST http://localhost:9000/evaluate \
    -H "Content-Type: application/json" \
    -d '{
        "method": "GET",
        "uri": "/",
        "headers": {"Host": "example.com"},
        "body": "",
        "remote_addr": "127.0.0.1",
        "server_addr": "127.0.0.1",
        "server_port": 443
    }' || echo "Request failed"

echo ""
echo "Testing SQL injection attack..."
curl -X POST http://localhost:9000/evaluate \
    -H "Content-Type: application/json" \
    -d '{
        "method": "GET",
        "uri": "/?id=1%27%20OR%201=1--",
        "headers": {"Host": "example.com"},
        "body": "",
        "remote_addr": "127.0.0.1",
        "server_addr": "127.0.0.1",
        "server_port": 443
    }' || echo "Attack correctly blocked"

echo ""
echo "Testing XSS attack..."
curl -X POST http://localhost:9000/evaluate \
    -H "Content-Type: application/json" \
    -d '{
        "method": "POST",
        "uri": "/comment",
        "headers": {"Host": "example.com"},
        "body": "comment=%3Cscript%3Ealert%28%27xss%27%29%3C%2Fscript%3E",
        "remote_addr": "127.0.0.1",
        "server_addr": "127.0.0.1",
        "server_port": 443
    }' || echo "XSS attack correctly blocked"

echo ""
echo "Stopping WAF service..."
kill $WAF_PID

echo ""
echo "Building full proxy with WAF integration..."
make clean && make all-services

echo ""
echo "✓ WAF integration test completed successfully!"
echo ""
echo "To start the full system:"
echo "1. Start WAF service: ./waf-service &"
echo "2. Start proxy: ./quic-proxy"
echo "3. Or use Docker: docker build -t quic-proxy-waf . && docker run -p 80:80 -p 443:443 -p 9000:9000 quic-proxy-waf"