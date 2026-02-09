# ddnsbridge4extdns

RFC2136 DNS UPDATE Bridge for Kubernetes ExternalDNS

## Overview

`ddnsbridge4extdns` is a lightweight RFC2136 DNS UPDATE server designed specifically for OPNsense DDNS integration with Kubernetes. It accepts DNS UPDATE messages (RFC2136) over UDP/TCP port 53, validates them using TSIG authentication, parses A/AAAA record create/update/delete operations, and translates them into Kubernetes DNSEndpoint resources that are consumed by ExternalDNS.

**Key Features:**
- ✅ RFC2136 DNS UPDATE protocol support (UDP & TCP)
- ✅ TSIG authentication (hmac-sha256, hmac-sha512, hmac-sha1, hmac-md5)
- ✅ A and AAAA record support
- ✅ Zone-scoped security (allow-list)
- ✅ Stateless and idempotent
- ✅ Native Kubernetes integration via DNSEndpoint CRD
- ✅ Lightweight and secure by default

**What it is NOT:**
- ❌ Not a DHCP server
- ❌ Not a DNS resolver
- ❌ Not an authoritative DNS server
- ❌ Not a full DNS server implementation

## Architecture

```
OPNsense DDNS Client
        ↓
   DNS UPDATE (RFC2136) over UDP/TCP:53
        ↓
   ddnsbridge4extdns (TSIG validation)
        ↓
   Kubernetes DNSEndpoint CRD
        ↓
   ExternalDNS
        ↓
   DNS Provider (Route53, Cloudflare, etc.)
```

## Prerequisites

- Kubernetes cluster (1.19+)
- ExternalDNS installed and configured
- DNSEndpoint CRD installed (comes with ExternalDNS)
- OPNsense or any RFC2136-compatible DDNS client

## Installation

### 1. Build the Docker Image

```bash
docker build -t ddnsbridge4extdns:latest .
```

### 2. Configure TSIG Credentials

Edit `deploy/kubernetes/deployment.yaml` and update the TSIG secret:

```yaml
stringData:
  tsig-key: "your-key-name"
  tsig-secret: "your-base64-secret"
```

Generate a TSIG secret:
```bash
# Generate a random secret
openssl rand -base64 32
```

### 3. Configure Allowed Zones

Edit `deploy/kubernetes/deployment.yaml` and update the allowed zones:

```yaml
data:
  ALLOWED_ZONES: "example.com,example.org,yourdomain.com"
```

### 4. Deploy to Kubernetes

```bash
kubectl apply -f deploy/kubernetes/deployment.yaml
```

### 5. Get the Service External IP

```bash
kubectl get svc -n ddnsbridge4extdns ddnsbridge4extdns
```

Note the `EXTERNAL-IP` - this is the IP address your OPNsense DDNS client should send updates to.

## Configuration

Configuration is done via environment variables:

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `LISTEN_ADDR` | Listen address | `0.0.0.0` | No |
| `PORT` | Listen port | `53` | No |
| `TSIG_KEY` | TSIG key name | - | **Yes** |
| `TSIG_SECRET` | TSIG shared secret | - | **Yes** |
| `TSIG_ALGORITHM` | TSIG algorithm | `hmac-sha256` | No |
| `NAMESPACE` | Target Kubernetes namespace for DNSEndpoints | `default` | No |
| `ALLOWED_ZONES` | Comma-separated list of allowed zones | - | **Yes** |
| `CUSTOM_LABELS` | Custom labels for DNSEndpoint resources (format: `key1=value1,key2=value2`) | - | No |
| `LOG_LEVEL` | Log level (TRACE, DEBUG, INFO, WARN, ERROR) | `INFO` | No |

### Supported Log Levels

- `TRACE` - Most verbose; logs all internal operations (values, computations, flow)
- `DEBUG` - Debug information; useful for troubleshooting (TSIG details, zone checks)
- `INFO` - Standard logging level; logs important events (DNS updates received, processed)
- `WARN` - Warning level; logs potentially problematic situations (rejected requests, zone mismatches)
- `ERROR` - Error level; logs errors only (failures, exceptions)

### Supported TSIG Algorithms

- `hmac-sha256` (recommended)
- `hmac-sha512`
- `hmac-sha1`

## OPNsense Configuration

1. Navigate to **Services → Dynamic DNS**
2. Add a new entry with these settings:
   - **Service**: RFC2136
   - **Server**: `<ddnsbridge4extdns-service-external-ip>`
   - **Zone**: Your zone (e.g., `example.com`)
   - **Key name**: Your TSIG key name (matches `TSIG_KEY`)
   - **Key**: Your TSIG secret (matches `TSIG_SECRET`)
   - **Key algorithm**: HMAC-SHA256 (or your chosen algorithm)
   - **Hostname**: The hostname to update (e.g., `router.example.com`)

## Testing

### Test with nsupdate

You can test the server using the `nsupdate` command:

```bash
# Create a key file
cat > /tmp/ddns.key <<EOF
key "your-key-name" {
    algorithm hmac-sha256;
    secret "your-base64-secret";
};
EOF

# Create an update file
cat > /tmp/update.txt <<EOF
server <ddnsbridge4extdns-ip> 53
zone example.com
update delete test.example.com A
update add test.example.com 300 A 192.168.1.100
send
EOF

# Send the update
nsupdate -k /tmp/ddns.key /tmp/update.txt
```

### Verify DNSEndpoint Creation

```bash
kubectl get dnsendpoint -n default
```

You should see a DNSEndpoint resource created for your update.

### Check Logs

```bash
kubectl logs -n ddnsbridge4extdns -l app=ddnsbridge4extdns -f
```

## Security Considerations

1. **TSIG Authentication**: All DNS UPDATE messages must be authenticated with TSIG. Unauthenticated requests are rejected.

2. **Zone-Scoped**: Only zones listed in `ALLOWED_ZONES` can be updated. This prevents unauthorized zone updates.

3. **Network Policies**: Consider using Kubernetes Network Policies to restrict access to the ddnsbridge4extdns service.

4. **Secret Management**: Store TSIG secrets securely using Kubernetes Secrets. Consider using external secret management solutions like Vault or Sealed Secrets.

5. **Minimal Permissions**: The service account has minimal RBAC permissions - only DNSEndpoint resources.

## ExternalDNS Integration

This server creates DNSEndpoint resources with the following structure:

```yaml
apiVersion: externaldns.k8s.io/v1alpha1
kind: DNSEndpoint
metadata:
  name: <sanitized-hostname>
  namespace: default
  labels:
    app.kubernetes.io/managed-by: ddnsbridge4extdns
    ddns-zone: <zone-name>
spec:
  endpoints:
  - dnsName: <fqdn>
    recordType: A  # or AAAA
    recordTTL: 300
    targets:
    - <ip-address>
```

ExternalDNS will automatically pick up these resources and create/update/delete the corresponding DNS records in your configured DNS provider.

## Building from Source

```bash
# Clone the repository
git clone https://github.com/tJouve/ddnsbridge4extdns.git
cd ddnsbridge4extdns

# Build
go build -o ddnsbridge4extdns ./cmd/server

# Run locally (requires kubeconfig)
export TSIG_KEY="your-key"
export TSIG_SECRET="your-secret"
export ALLOWED_ZONES="example.com"
./ddnsbridge4extdns
```

## Development

### Project Structure

```
.
├── cmd/
│   └── server/          # Main application entry point
├── pkg/
│   ├── config/          # Configuration management
│   ├── tsig/            # TSIG validation
│   ├── update/          # DNS UPDATE parser
│   └── k8s/             # Kubernetes client
├── internal/
│   └── handler/         # DNS request handler
├── deploy/
│   └── kubernetes/      # Kubernetes manifests
├── Dockerfile
└── README.md
```

### Running Tests

```bash
go test ./...
```

## Troubleshooting

### DNS UPDATE rejected with NOTAUTH

- Verify TSIG key name matches between OPNsense and ddnsbridge4extdns
- Verify TSIG secret matches (base64-encoded)
- Verify TSIG algorithm matches
- Check logs: `kubectl logs -n ddnsbridge4extdns -l app=ddnsbridge4extdns`

### DNS UPDATE rejected with REFUSED

- Verify the zone is in the `ALLOWED_ZONES` list
- Ensure the zone name in OPNsense matches exactly (with or without trailing dot)

### DNSEndpoint not created

- Verify the service account has proper RBAC permissions
- Check if DNSEndpoint CRD is installed: `kubectl get crd dnsendpoints.externaldns.k8s.io`
- Check namespace configuration matches where ExternalDNS is watching

### ExternalDNS not picking up DNSEndpoint

- Verify ExternalDNS is configured to watch DNSEndpoint resources
- Check ExternalDNS source configuration includes `crd`
- Verify the namespace matches ExternalDNS watch configuration

## License

MIT License - see LICENSE file for details

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## Author

Created for OPNsense DDNS integration with Kubernetes ExternalDNS.
