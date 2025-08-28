#!/bin/bash

# Build script for Kubernetes deployment
set -e

# Configuration
REGISTRY="${REGISTRY:-ghcr.io/pmh-only/quic-proxy}"
TAG="${TAG:-latest}"

echo "Building container images..."

# Build WAF service image
echo "Building Coraza WAF service..."
cd waf
docker build -t ${REGISTRY}/coraza-waf:${TAG} .
cd ..

# Build proxy service image  
echo "Building QUIC Reverse Proxy..."
docker build -t ${REGISTRY}/quic-proxy:${TAG} .

echo "✓ Container images built successfully!"
echo ""
echo "Images:"
echo "  - ${REGISTRY}/coraza-waf:${TAG}"
echo "  - ${REGISTRY}/quic-proxy:${TAG}"
echo ""

# Push to registry if PUSH=true
if [ "${PUSH:-false}" = "true" ]; then
    echo "Pushing images to registry..."
    docker push ${REGISTRY}/coraza-waf:${TAG}
    docker push ${REGISTRY}/quic-proxy:${TAG}
    echo "✓ Images pushed to registry!"
fi

echo "To deploy to Kubernetes:"
echo "  kubectl apply -f k8s/"