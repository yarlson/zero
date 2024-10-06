# Zero - Go ACME Client for ZeroSSL

## Problem

Nginx servers need SSL/TLS certificates for secure connections. Existing solutions like Certbot are often too large and complex for simple setups.

## Solution

Zero is a lightweight Go ACME client for obtaining and renewing SSL/TLS certificates from ZeroSSL using the ACME protocol.

## Features

- Obtains and renews SSL/TLS certificates from ZeroSSL
- Supports HTTP-01 challenge
- Automatic renewal before expiration
- Minimal dependencies
- Automatic retrieval of ZeroSSL credentials using email
- Configurable certificate storage directory
- POSIX-compatible command-line interface

## Requirements

- Go 1.16 or later

## Installation

```
go install github.com/yarlson/zero@latest
```

## Usage

```
zero -d example.com -e user@example.com [-c /path/to/certs] [-i] [-r]
```

or using long-form flags:

```
zero --domain example.com --email user@example.com [--cert-dir /path/to/certs] [--issue] [--renew]
```

Options:

- `-d, --domain`: Domain name for the certificate (required)
- `-e, --email`: Email address for credential retrieval and account registration (required)
- `-c, --cert-dir`: Directory to store certificates (default: "./certs")
- `-i, --issue`: Force issuance of a new certificate
- `-r, --renew`: Force renewal of an existing certificate

Without `--issue` or `--renew`, Zero checks the existing certificate and renews if needed.

For more information, run:

```
zero --help
```

## Configuration

Certificates are stored in the `./certs` directory by default. Use the `--cert-dir` flag to specify a custom directory for certificate storage.

## Limitations

- Only supports HTTP-01 challenge
- Designed for single-domain certificates
- No support for wildcard certificates

## Contributing

Contributions are welcome. Please submit pull requests with clear descriptions of changes and updates to tests if applicable.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
