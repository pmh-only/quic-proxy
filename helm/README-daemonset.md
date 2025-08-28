# DaemonSet Deployment Mode

This Helm chart supports deploying the QUIC proxy as a DaemonSet with host port binding for edge computing scenarios.

## When to Use DaemonSet Mode

- **Edge Computing**: Deploy proxy on every edge node for minimal latency
- **Direct Host Access**: Need direct access to node ports without load balancer
- **Hardware Load Balancers**: Using external hardware load balancers instead of Kubernetes services
- **Single-Node Clusters**: Running on single-node or bare-metal clusters
- **Cost Optimization**: Avoid cloud load balancer costs

## Configuration

### Basic DaemonSet Deployment

```yaml
proxy:
  kind: daemonset
  ports:
    useHostPorts: true

daemonset:
  hostNetwork: true
  dnsPolicy: ClusterFirstWithHostNet
```

### Example Values

Use the provided `values-daemonset.yaml` file:

```bash
helm install my-proxy ./helm \
  --values ./helm/values-daemonset.yaml \
  --set proxy.backend.host=my-backend-service
```

## Key Differences from Deployment Mode

| Feature | Deployment | DaemonSet |
|---------|------------|-----------|
| **Scheduling** | Based on replicas | One pod per node |
| **Service** | LoadBalancer/ClusterIP | Disabled (direct host access) |
| **Host Ports** | Optional | Recommended |
| **Host Network** | No | Optional |
| **PodDisruptionBudget** | Yes | Not applicable |
| **Scaling** | Manual replica count | Automatic (node count) |

## Port Configuration

### With Host Ports (Recommended)

```yaml
proxy:
  kind: daemonset
  ports:
    http: 80
    https: 443
    useHostPorts: true
```

This creates:
- HTTP on port 80 (TCP) - accessible via `http://<node-ip>/`
- HTTPS on port 443 (TCP) - accessible via `https://<node-ip>/`
- HTTP/3 on port 443 (UDP) - for QUIC protocol

### Without Host Ports

```yaml
proxy:
  kind: daemonset
  ports:
    useHostPorts: false
```

Standard Kubernetes Service will be created for cluster-internal access.

## Node Selection

### Target Specific Nodes

```yaml
nodeSelector:
  node-role.kubernetes.io/edge: "true"
```

### Tolerate Taints

```yaml
tolerations:
- key: "edge"
  operator: "Equal"
  value: "true"
  effect: "NoSchedule"
```

### Anti-Affinity (Deployment Mode Only)

```yaml
affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
    - weight: 100
      podAffinityTerm:
        labelSelector:
          matchExpressions:
          - key: app.kubernetes.io/name
            operator: In
            values:
            - quic-proxy-waf
        topologyKey: kubernetes.io/hostname
```

## Update Strategy

DaemonSets support rolling updates:

```yaml
daemonset:
  updateStrategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 1  # Update one node at a time
```

## Security Considerations

### Host Network Access

When using `hostNetwork: true`:

```yaml
daemonset:
  hostNetwork: true
  dnsPolicy: ClusterFirstWithHostNet
```

**Implications:**
- Pod uses host's network namespace
- Direct access to all host network interfaces
- Potential security risk - use with caution
- Required for some edge computing scenarios

### Required Permissions

The proxy needs root privileges for port 80/443 binding:

```yaml
securityContext:
  runAsNonRoot: false
  runAsUser: 0
```

**Container capabilities:**
```yaml
securityContext:
  capabilities:
    add:
    - NET_BIND_SERVICE
    drop:
    - ALL
```

## Monitoring and Health Checks

Health check endpoint remains available:
- With host ports: `http://<node-ip>/_gwhealthz`  
- Without host ports: `http://<service-ip>/_gwhealthz`

## Complete Example

```yaml
# Production edge deployment
global:
  registry: ghcr.io/pmh-only/quic-proxy
  tag: "v1.1.0"

proxy:
  kind: daemonset
  backend:
    host: "api-backend.internal"
    port: 8080
  ports:
    useHostPorts: true

waf:
  enabled: true
  replicaCount: 3

daemonset:
  hostNetwork: true
  dnsPolicy: ClusterFirstWithHostNet
  updateStrategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 1

nodeSelector:
  node-role.kubernetes.io/edge: "true"

tolerations:
- key: "edge-taint"
  operator: "Exists"
  effect: "NoSchedule"
```

## Troubleshooting

### Port Conflicts

If host ports are already in use:
```bash
# Check port usage on nodes
ss -tulpn | grep ':80\|:443'

# Use different ports
proxy:
  ports:
    http: 8080
    https: 8443
    useHostPorts: true
```

### DNS Resolution

With `hostNetwork: true`, use `ClusterFirstWithHostNet`:
```yaml
daemonset:
  dnsPolicy: ClusterFirstWithHostNet
```

### Node Affinity

Ensure nodes are labeled correctly:
```bash
kubectl label nodes node1 node-role.kubernetes.io/edge=true
kubectl get nodes --show-labels
```