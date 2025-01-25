# Zero - Go ACME Client for ZeroSSL

## Problem

Nginx servers need SSL/TLS certificates for secure connections. Existing solutions like Certbot are often too large and complex for simple setups.

## Solution

Zero is a lightweight Go ACME client for obtaining and renewing SSL/TLS certificates from ZeroSSL using the ACME protocol. It runs as a daemon, serving HTTP-01 challenges and automatically managing certificate renewals.

## Features

- Obtains and renews SSL/TLS certificates from ZeroSSL
- Runs as a daemon with automatic daily certificate checks
- Serves HTTP-01 challenges and redirects HTTP to HTTPS
- Automatic renewal before expiration (30 days)
- Minimal dependencies
- Automatic retrieval of ZeroSSL credentials using email
- Configurable certificate storage directory
- POSIX-compatible command-line interface

## Requirements

- Go 1.16 or later

## Installation

```bash
go install github.com/yarlson/zero@latest
```

## Usage

Basic usage:

```bash
sudo zero -d example.com -e user@example.com
```

With all options:

```bash
sudo zero -d example.com -e user@example.com [-c /path/to/certs] [-p port] [-t HH:mm]
```

Options:

- `-d, --domain`: Domain name for the certificate (required)
- `-e, --email`: Email address for credential retrieval and account registration (required)
- `-c, --cert-dir`: Directory to store certificates (default: "./certs")
- `-p, --port`: HTTP port for ACME challenges (default: 80)
- `-t, --time`: Time for daily renewal checks in HH:mm format (default: "02:00")

For more information, run:

```bash
zero --help
```

## Operation

Zero operates as a daemon that:

1. Serves HTTP-01 challenges on port 80 (required by ACME protocol)
2. Redirects all other HTTP traffic to HTTPS
3. Checks certificates daily at the specified time
4. Automatically obtains or renews certificates when needed
5. Handles graceful shutdown on SIGINT/SIGTERM

## Configuration

Certificates are stored in the `./certs` directory by default. Use the `--cert-dir` flag to specify a custom directory for certificate storage.

The daemon will check certificates daily at 02:00 by default. Use the `--time` flag to specify a different time in 24-hour format.

## Limitations

- Only supports HTTP-01 challenge
- Designed for single-domain certificates
- No support for wildcard certificates

## Contributing

Contributions are welcome. Please submit pull requests with clear descriptions of changes and updates to tests if applicable.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
