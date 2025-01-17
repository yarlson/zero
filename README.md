# Zero SSL Certificate Manager

A Go-based CLI tool for automated SSL certificate management using ZeroSSL's ACME service, with support for clustered deployments.

## Features

- Automated SSL certificate issuance and renewal
- HTTP-01 challenge verification
- Cluster support for distributed certificate management
- Cron mode for automated renewals
- Configurable certificate storage location
- Graceful shutdown handling

## Installation

```bash
go install github.com/yarlson/zero@latest
```

## Usage

Basic certificate issuance:

```bash
zero -d example.com -e user@example.com --issue
```

Certificate renewal:

```bash
zero -d example.com -e user@example.com --renew
```

Automated mode (issues if missing, renews if expiring):

```bash
zero -d example.com -e user@example.com
```

### Cron Mode

Run with daily renewal checks:

```bash
zero -d example.com -e user@example.com --cron --time "02:00"
```

### Cluster Mode

Run in cluster mode:

```bash
# First node
zero -d example.com -e user@example.com --cluster --cluster-addr "localhost:5000"

# Additional nodes
zero -d example.com -e user@example.com --cluster \
  --cluster-addr "localhost:5001" \
  --seed-nodes "localhost:5000"
```

## Configuration

Command line options:

```
  -d, --domain string         Domain name for the certificate
  -e, --email string         Email address for account registration
  -c, --cert-dir string      Directory to store certificates (default "./certs")
  -i, --issue                Issue a new certificate
  -r, --renew                Renew the existing certificate
      --cron                 Run in cron mode for daily renewals
      --time string          Time for daily renewal in HH:mm format (default "02:00")
      --cluster             Enable cluster mode
      --cluster-addr string  Address for cluster communication (default "localhost:5000")
      --seed-nodes strings   List of seed nodes to join cluster
```

## Cluster Architecture

The cluster mode provides:

- Distributed certificate storage
- Leader election for coordinated operations
- Automatic node health monitoring
- gRPC-based inter-node communication
- Certificate and challenge synchronization

### Cluster Configuration

```go
type Config struct {
    InstanceID   string        // Unique identifier for this instance
    BindAddress  string        // Address for cluster communication
    SeedNodes    []string      // List of seed nodes to join cluster
    TLSConfig    *tls.Config   // Optional TLS configuration
    StateDir     string        // Directory for cluster state
}
```

## Development

Requirements:

- Go 1.23 or later
- Protocol Buffers compiler (protoc)
- Make

Building:

```bash
# Install dependencies
make deps

# Generate protobuf code
make proto

# Build
go build
```

## License

[License details here]
