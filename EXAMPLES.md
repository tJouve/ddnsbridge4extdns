# Usage Examples

## Running Locally

### Prerequisites
- Go 1.24+
- kubectl configured with access to a Kubernetes cluster
- ExternalDNS installed in the cluster

### Environment Setup

```bash
export TSIG_KEY="opnsense-ddns."
export TSIG_SECRET="bXktc2VjcmV0LWtleQ=="  # Base64-encoded secret
export ALLOWED_ZONES="example.com,home.example.com"
export NAMESPACE="default"
export PORT="5353"  # Use non-privileged port for local testing
```

### Generate TSIG Secret

```bash
# Generate a random secret
openssl rand -base64 32
```

### Run the Server

```bash
go run ./cmd/server
```

## Testing with nsupdate

### Create TSIG Key File

```bash
cat > ddns.key <<EOF
key "opnsense-ddns." {
    algorithm hmac-sha256;
    secret "bXktc2VjcmV0LWtleQ==";
};
EOF
```
or use
```bash
tsig-keygen -a hmac-sha256 opnsense-ddns. >  ddns.key
```
### Send a DNS UPDATE

```bash
# Add an A record
nsupdate -k ddns.key <<EOF
server 127.0.0.1 5353
zone example.com
update add router.example.com 300 A 192.168.1.1
send
EOF

# Add an AAAA record
nsupdate -k ddns.key <<EOF
server 127.0.0.1 5353
zone example.com
update add router.example.com 300 AAAA 2001:db8::1
send
EOF

# Delete a record
nsupdate -k ddns.key <<EOF
server 127.0.0.1 5353
zone example.com
update delete router.example.com A
send
EOF
```

### Verify DNSEndpoint Creation

```bash
kubectl get dnsendpoint -n default
kubectl get dnsendpoint router-example-com -n default -o yaml
```

## OPNsense Configuration

### Step 1: Navigate to Dynamic DNS

1. Log in to OPNsense web interface
2. Go to **Services** → **Dynamic DNS**
3. Click **+** to add a new entry

### Step 2: Configure RFC2136

- **Enabled**: ✓ Check
- **Service**: RFC2136
- **Server**: `<your-ddnsbridge4extdns-service-ip>` (Get from `kubectl get svc -n ddnsbridge4extdns`)
- **Zone**: `example.com`
- **Key name**: `opnsense-ddns.`
- **Key**: `bXktc2VjcmV0LWtleQ==` (your base64-encoded secret)
- **Key algorithm**: HMAC-SHA256
- **Hostname**: `router` (will become router.example.com)
- **Check ip method**: Interface
- **Interface to monitor**: WAN

### Step 3: Force Update

Click the force update button (refresh icon) to trigger an immediate update.

### Step 4: Verify

Check the OPNsense logs:
- Go to **System** → **Log Files** → **General**
- Look for "DDNS" entries

Check Kubernetes:
```bash
kubectl logs -n ddnsbridge4extdns -l app=ddnsbridge4extdns -f
kubectl get dnsendpoint -n default
```

## Kubernetes Deployment

### Step 1: Build and Push Docker Image

```bash
docker build -t your-registry/ddnsbridge4extdns:latest .
docker push your-registry/ddnsbridge4extdns:latest
```

### Step 2: Update Deployment Manifest

Edit `deploy/kubernetes/deployment.yaml`:

1. Update the image:
   ```yaml
   image: your-registry/ddnsbridge4extdns:latest
   ```

2. Update TSIG credentials:
   ```yaml
   stringData:
     tsig-key: "opnsense-ddns."
     tsig-secret: "your-base64-secret"
   ```

3. Update allowed zones:
   ```yaml
   data:
     ALLOWED_ZONES: "example.com,home.example.com"
   ```

### Step 3: Deploy

```bash
kubectl apply -f deploy/kubernetes/deployment.yaml
```

### Step 4: Get Service IP

```bash
kubectl get svc -n ddnsbridge4extdns ddnsbridge4extdns
```

Use the `EXTERNAL-IP` in your OPNsense configuration.

## Troubleshooting

### Check Server Logs

```bash
kubectl logs -n ddnsbridge4extdns -l app=ddnsbridge4extdns -f
```

### Common Errors

#### "TSIG validation failed"
- Verify TSIG key name matches exactly (including trailing dot if present)
- Verify TSIG secret is base64-encoded
- Verify TSIG algorithm matches (hmac-sha256 is recommended)

#### "Zone not allowed"
- Check that the zone is listed in `ALLOWED_ZONES`
- Ensure zone name format matches (with or without trailing dot)

#### "DNSEndpoint not created"
- Verify service account has proper RBAC permissions
- Check that DNSEndpoint CRD is installed: `kubectl get crd dnsendpoints.externaldns.k8s.io`
- Verify namespace configuration

#### "ExternalDNS not updating DNS"
- Verify ExternalDNS is running: `kubectl get pods -n external-dns`
- Check ExternalDNS logs: `kubectl logs -n external-dns -l app.kubernetes.io/name=external-dns`
- Verify ExternalDNS is configured to watch DNSEndpoint CRDs
- Check ExternalDNS source configuration includes `crd`

### Debug Mode

Enable more verbose logging:

```yaml
data:
  LOG_LEVEL: "debug"
```

## Security Best Practices

### 1. Use Strong TSIG Secrets

```bash
# Generate a strong 256-bit secret
openssl rand -base64 32
```

### 2. Restrict Network Access

Use Kubernetes NetworkPolicies to restrict access to the ddnsbridge4extdns service:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: ddnsbridge4extdns-ingress
  namespace: ddnsbridge4extdns
spec:
  podSelector:
    matchLabels:
      app: ddnsbridge4extdns
  policyTypes:
  - Ingress
  ingress:
  - from:
    - ipBlock:
        cidr: 192.168.1.0/24  # Your OPNsense network
    ports:
    - protocol: UDP
      port: 53
    - protocol: TCP
      port: 53
```

### 3. Use Sealed Secrets

Instead of plain Kubernetes Secrets, use [Sealed Secrets](https://github.com/bitnami-labs/sealed-secrets):

```bash
# Install sealed-secrets controller
kubectl apply -f https://github.com/bitnami-labs/sealed-secrets/releases/download/v0.24.0/controller.yaml

# Create a sealed secret
kubectl create secret generic ddns-tsig \
  --from-literal=tsig-key="opnsense-ddns." \
  --from-literal=tsig-secret="your-secret" \
  --dry-run=client -o yaml | \
  kubeseal -o yaml > sealed-secret.yaml

# Apply the sealed secret
kubectl apply -f sealed-secret.yaml
```

### 4. Limit Zone Scope

Only configure zones that you actually need to update:

```yaml
data:
  ALLOWED_ZONES: "home.example.com"  # Not "example.com"
```

### 5. Monitor Logs

Set up log aggregation and alerting for security events:
- Failed TSIG validations
- Rejected zone updates
- Unusual update patterns

## Integration with ExternalDNS

### ExternalDNS Configuration

Ensure ExternalDNS is configured to watch DNSEndpoint resources:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: external-dns
spec:
  template:
    spec:
      containers:
      - name: external-dns
        args:
        - --source=crd                    # Enable CRD source
        - --crd-source-apiversion=externaldns.k8s.io/v1alpha1
        - --crd-source-kind=DNSEndpoint
        - --domain-filter=example.com     # Optional: filter domains
        - --provider=cloudflare           # Your DNS provider
        # ... other provider-specific args
```

### Supported DNS Providers

ddnsbridge4extdns works with any DNS provider supported by ExternalDNS:

- AWS Route53
- Cloudflare
- Google Cloud DNS
- Azure DNS
- DigitalOcean
- Linode
- And many more...

Configure ExternalDNS according to your provider's documentation.
