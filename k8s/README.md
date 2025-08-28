# QUIC Proxy with Coraza WAF - Kubernetes Deployment

This directory contains Kubernetes manifests for deploying the QUIC reverse proxy with integrated Coraza WAF.

**Repository**: https://github.com/pmh-only/quic-proxy  
**Images**: https://github.com/pmh-only/quic-proxy/pkgs/container/quic-proxy%2Fquic-proxy

## Architecture

- **Proxy Service**: C++ reverse proxy with HTTP/1.1, HTTP/2, HTTP/3, and WebSocket support
- **WAF Service**: Go-based Coraza WAF with OWASP Core Rule Set v4
- **Communication**: Proxy communicates with WAF via HTTP API
- **Security**: Network policies restrict inter-pod communication

## Quick Start

### 1. Build Images

```bash
# Make build script executable
chmod +x build-images.sh

# Build both images
./build-images.sh

# Or build and push to registry
REGISTRY=your-registry.com/project PUSH=true ./build-images.sh
```

### 2. Create TLS Secret

```bash
# Create TLS certificate secret (replace with your cert/key)
kubectl create secret tls tls-certificate \
  --cert=path/to/your/cert.pem \
  --key=path/to/your/key.pem \
  -n quic-proxy
```

### 3. Deploy

```bash
# Deploy using kubectl
kubectl apply -f k8s/

# Or using kustomize
kubectl apply -k k8s/
```

## Configuration

### Environment Variables

Edit `proxy-configmap.yaml` to configure:

- `BACKEND_HOST`: Your backend service hostname
- `BACKEND_PORT`: Your backend service port
- `WAF_ENABLED`: Enable/disable WAF (true/false)
- `WAF_TIMEOUT_MS`: WAF request timeout in milliseconds

### Scaling

Adjust replica counts in deployment files:
- `proxy-deployment.yaml`: Proxy replicas (default: 3)
- `waf-deployment.yaml`: WAF replicas (default: 2)

## Monitoring

### Health Checks

- Proxy: `http://proxy-pod/_gwhealthz`
- WAF: `http://waf-pod:9000/health`

### Logs

```bash
# View proxy logs
kubectl logs -f deployment/quic-proxy -n quic-proxy

# View WAF logs
kubectl logs -f deployment/coraza-waf -n quic-proxy

# View blocked requests
kubectl logs -f deployment/quic-proxy -n quic-proxy | grep "WAF BLOCKED"
```

## Security Features

### Network Policies

- Proxy pods can only communicate with WAF and backend services
- WAF pods only accept connections from proxy pods
- External traffic only allowed to proxy on ports 80/443

### Pod Security

- WAF runs as non-root user (65534)
- Read-only root filesystem for WAF
- Minimal capabilities
- Resource limits enforced

## Troubleshooting

### WAF Connection Issues

```bash
# Check WAF service connectivity from proxy pod
kubectl exec -it deployment/quic-proxy -n quic-proxy -- \
  curl http://coraza-waf-service:9000/health
```

### Certificate Issues

```bash
# Check TLS secret
kubectl get secret tls-certificate -n quic-proxy -o yaml

# Verify certificate mounting
kubectl exec -it deployment/quic-proxy -n quic-proxy -- \
  ls -la /etc/ssl/certs/
```

### Performance Tuning

- Increase WAF replicas for high traffic
- Adjust resource limits based on usage
- Consider horizontal pod autoscaling for proxy pods

## Files

- `namespace.yaml`: Creates quic-proxy namespace
- `waf-deployment.yaml`: WAF service deployment
- `waf-service.yaml`: WAF ClusterIP service
- `proxy-configmap.yaml`: Proxy configuration
- `proxy-deployment.yaml`: Proxy deployment
- `proxy-service.yaml`: Proxy LoadBalancer service
- `network-policy.yaml`: Network security policies
- `pod-disruption-budget.yaml`: High availability configuration
- `kustomization.yaml`: Kustomize configuration