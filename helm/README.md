# QUIC Proxy with Coraza WAF - Helm Chart

This Helm chart deploys a high-performance reverse proxy with integrated Coraza WAF and OWASP Core Rule Set on Kubernetes.

**Repository**: https://github.com/pmh-only/quic-proxy  
**Helm Repository**: https://pmh-only.github.io/quic-proxy/charts  
**Images**: https://github.com/pmh-only/quic-proxy/pkgs/container/quic-proxy%2Fquic-proxy

## Prerequisites

- Kubernetes 1.20+
- Helm 3.0+
- TLS certificate and private key

## Installation

### 1. Add Repository

```bash
helm repo add quic-proxy https://pmh-only.github.io/quic-proxy/charts
helm repo update
```

### 2. Create TLS Secret

```bash
kubectl create namespace quic-proxy
kubectl create secret tls tls-certificate \
  --cert=path/to/your/cert.pem \
  --key=path/to/your/key.pem \
  -n quic-proxy
```

### 3. Install Chart

```bash
# Install with default values
helm install my-proxy quic-proxy/quic-proxy-waf -n quic-proxy

# Or install from local directory
helm install my-proxy ./helm -n quic-proxy

# With custom values
helm install my-proxy quic-proxy/quic-proxy-waf -n quic-proxy -f my-values.yaml
```

## Configuration

### Basic Configuration

Create a `values.yaml` file:

```yaml
proxy:
  backend:
    host: "my-backend-service"
    port: 8080

service:
  type: LoadBalancer
  annotations:
    service.beta.kubernetes.io/aws-load-balancer-type: "nlb"

# Scale for production
proxy:
  replicaCount: 5
waf:
  replicaCount: 3
```

### Advanced Configuration

```yaml
# Disable WAF (not recommended for production)
waf:
  enabled: false

# Custom resource limits
proxy:
  resources:
    requests:
      memory: "256Mi"
      cpu: "500m"
    limits:
      memory: "1Gi"
      cpu: "2000m"

# Node placement
nodeSelector:
  kubernetes.io/instance-type: "m5.large"

affinity:
  podAntiAffinity:
    requiredDuringSchedulingIgnoredDuringExecution:
    - labelSelector:
        matchExpressions:
        - key: app.kubernetes.io/component
          operator: In
          values:
          - proxy
      topologyKey: "kubernetes.io/hostname"
```

## Values Reference

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `global.registry` | string | `"quic-proxy"` | Container registry |
| `global.tag` | string | `"1.2.3"` | Image tag |
| `global.imagePullPolicy` | string | `"IfNotPresent"` | Image pull policy |
| `waf.enabled` | bool | `true` | Enable WAF service |
| `waf.replicaCount` | int | `2` | Number of WAF replicas |
| `proxy.replicaCount` | int | `3` | Number of proxy replicas |
| `proxy.backend.host` | string | `"your-backend-service"` | Backend service hostname |
| `proxy.backend.port` | int | `8080` | Backend service port |
| `proxy.waf.enabled` | bool | `true` | Enable WAF integration |
| `proxy.waf.timeout` | int | `1000` | WAF timeout in milliseconds |
| `service.type` | string | `"LoadBalancer"` | Kubernetes service type |
| `networkPolicy.enabled` | bool | `true` | Enable network policies |
| `podDisruptionBudget.enabled` | bool | `true` | Enable pod disruption budgets |

## Monitoring and Operations

### Health Checks

```bash
# Check deployment status
kubectl get pods -n quic-proxy

# View logs
kubectl logs -f deployment/my-proxy-quic-proxy-waf-proxy -n quic-proxy
kubectl logs -f deployment/my-proxy-quic-proxy-waf-waf -n quic-proxy
```

### Scaling

```bash
# Scale proxy
kubectl scale deployment my-proxy-quic-proxy-waf-proxy --replicas=5 -n quic-proxy

# Scale WAF
kubectl scale deployment my-proxy-quic-proxy-waf-waf --replicas=3 -n quic-proxy
```

### Upgrading

```bash
# Upgrade with new image version
helm upgrade my-proxy ./helm -n quic-proxy --set global.tag=v1.1.0

# Upgrade with new values
helm upgrade my-proxy ./helm -n quic-proxy -f new-values.yaml
```

## Security Considerations

### Network Policies

The chart includes network policies that:
- Allow external traffic only to proxy pods on ports 80/443
- Allow proxy to WAF communication only on port 9000
- Allow proxy to backend communication
- Deny all other inter-pod communication

### Pod Security

- WAF runs as non-root user with read-only filesystem
- Minimal Linux capabilities granted
- Resource limits enforced
- Security contexts configured

### WAF Protection

Built-in OWASP Core Rule Set protects against:
- SQL Injection
- Cross-Site Scripting (XSS)
- Path Traversal
- Command Injection
- Rate limiting attacks

## Troubleshooting

### Common Issues

1. **Proxy can't connect to WAF**
   ```bash
   kubectl exec -it deployment/my-proxy-quic-proxy-waf-proxy -n quic-proxy -- \
     nslookup my-proxy-quic-proxy-waf-waf
   ```

2. **TLS certificate issues**
   ```bash
   kubectl get secret tls-certificate -n quic-proxy -o yaml
   ```

3. **Backend connectivity**
   ```bash
   kubectl logs -f deployment/my-proxy-quic-proxy-waf-proxy -n quic-proxy | grep "Backend"
   ```

### Support

- Check logs: `kubectl logs -f deployment/<name> -n quic-proxy`
- View events: `kubectl get events -n quic-proxy`
- Describe pods: `kubectl describe pod <pod-name> -n quic-proxy`

## Uninstallation

```bash
helm uninstall my-proxy -n quic-proxy
kubectl delete namespace quic-proxy
```
