# Zero - SSL Certificate Manager

## Problem

Nginx servers need SSL/TLS certificates for secure connections. Existing solutions like Certbot are often too large and complex for simple setups.

## Solution

Zero is a lightweight service that manages SSL/TLS certificates using ZeroSSL. It automatically handles certificate obtainment, renewal, and HTTP challenges while running as a background service.

## Features

Core Features:
- Automatic SSL/TLS certificate management via ZeroSSL
- Support for multiple domains in a single certificate (SAN certificates)
- Daily certificate monitoring and renewal (30 days before expiration)
- Built-in HTTP server for ACME challenges
- HTTP to HTTPS traffic redirection
- Post-renewal hooks with Docker container support

Deployment:
- Available as a Docker image (AMD64/ARM64)
- Minimal dependencies
- Simple command-line interface
- Configurable certificate storage
- Configurable renewal schedule

Integration:
- Works seamlessly with Nginx
- Easy to use with Docker Compose
- Automatic ZeroSSL account management

## Requirements

- Go 1.23 or later

## Installation

Download the latest release from the [releases page](https://github.com/yarlson/zero/releases/latest).

### macOS

1. Download the appropriate archive for your system architecture:

   - For AMD64 (Intel): `zero_*_darwin_amd64.tar.gz`
   - For ARM64 (Apple Silicon): `zero_*_darwin_arm64.tar.gz`

2. Extract the binary:

   ```bash
   tar xzf zero_*.tar.gz
   ```

3. Make the binary executable and move it to your local bin directory:

   ```bash
   chmod +x ./zero
   sudo mv ./zero /usr/local/bin/
   ```

4. Remove the macOS security quarantine attribute:
   ```bash
   sudo xattr -d com.apple.quarantine /usr/local/bin/zero
   ```

### Linux

1. Download the appropriate archive for your system architecture:

   - For AMD64: `zero_*_linux_amd64.tar.gz`
   - For ARM64: `zero_*_linux_arm64.tar.gz`

2. Extract the binary:

   ```bash
   tar xzf zero_*.tar.gz
   ```

3. Make the binary executable and move it to your local bin directory:
   ```bash
   chmod +x ./zero
   sudo mv ./zero /usr/local/bin/
   ```

### Windows

1. Download the appropriate archive for your system architecture:

   - For Windows AMD64: `zero_*_windows_amd64.tar.gz`
   - For Windows ARM64: `zero_*_windows_arm64.tar.gz`

2. Extract the archive using your preferred archive tool

3. Add the extracted binary location to your system's PATH environment variable

### From Source

If you have Go 1.23 or later installed:

```bash
go install github.com/yarlson/zero@latest
```

### Using Docker

Pull and run the latest image:

```bash
docker pull yarlson/zero:latest
```

See the [Docker](#docker) section for detailed usage instructions.

### Verify Installation

To verify the installation:
```bash
zero --help
```

## Usage

Basic usage for a single domain:

```bash
zero -d example.com -e user@example.com
```

With multiple domains:

```bash
zero -d example.com,www.example.com -e user@example.com
```

Or by specifying the domain flag multiple times:

```bash
zero -d example.com -d www.example.com -e user@example.com
```

With all options:

```bash
zero -d example.com -e user@example.com [-c /path/to/certs] [-p port] [-t HH:mm]
```

Options:

- `-d, --domain`: Domain name(s) for the certificate (comma-separated or repeated, at least one required)
- `-e, --email`: Email address for credential retrieval and account registration (required)
- `-c, --cert-dir`: Directory to store certificates (default: "./certs")
- `-p, --port`: HTTP port for ACME challenges (default: 80)
- `-t, --time`: Time for daily renewal checks in HH:mm format (default: "02:00")
- `--hook`: Command to execute after certificate renewal
- `--hook-container`: Container name or network alias to execute hook in

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
5. Executes configured hooks after certificate renewal
5. Handles graceful shutdown on SIGINT/SIGTERM

## Configuration

Certificates are stored in the `./certs` directory by default. Use the `--cert-dir` flag to specify a custom directory for certificate storage.

The daemon will check certificates daily at 02:00 by default. Use the `--time` flag to specify a different time in 24-hour format.

### Post-Renewal Hooks

You can configure commands to be executed after certificate renewal using hooks:

```bash
# Execute local command after renewal
zero -d example.com -e user@example.com --hook "systemctl reload nginx"

# Execute command in Docker container after renewal
zero -d example.com -e user@example.com \
  --hook "nginx -s reload" \
  --hook-container "nginx-container"
```

When using `--hook-container`, Zero will:
1. Find the container by name or network alias
2. Execute the specified command inside that container
3. Wait for command completion

This is particularly useful for reloading Nginx configuration after certificate renewal.

## Limitations

- Only supports HTTP-01 challenge
- No support for wildcard certificates

## Contributing

Contributions are welcome. Please submit pull requests with clear descriptions of changes and updates to tests if applicable.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Docker

Zero is available as a Docker image supporting both AMD64 and ARM64 architectures.

Basic usage:
```bash
docker run -d \
  --name zero \
  -p 80:80 \
  -v /path/to/certs:/certs \
  yarlson/zero:latest \
  -d example.com \
  -e user@example.com \
  -c /certs
```

Options:
- `-d`: Run container in background
- `-p 80:80`: Map container's port 80 to host's port 80 (required for ACME challenges)
- `-v /path/to/certs:/certs`: Mount local directory for certificate storage
- `yarlson/zero:latest`: Use latest version (or specify a version like `yarlson/zero:0.3.7`)

The certificates will be stored in the mounted volume at `/path/to/certs` on the host.

### Docker Compose

Example docker-compose.yml:
```yaml
volumes:
  certs:  # Named volume for certificates

services:
  zero:
    image: yarlson/zero:latest
    ports:
      - "80:80"
    volumes:
      - certs:/certs
    command:
      - -d
      - example.com
      - -e
      - user@example.com
      - -c
      - /certs
    restart: unless-stopped
```

### Using with Nginx

Example docker-compose.yml with Nginx:
```yaml
volumes:
  certs:  # Named volume for certificates

services:
  zero:
    image: yarlson/zero:latest
    ports:
      - "80:80"
    volumes:
      - certs:/certs
    command:
      - -d
      - example.com
      - -e
      - user@example.com
      - -c
      - /certs
      - --hook
      - nginx -s reload
      - --hook-container
      - nginx
    restart: unless-stopped

  nginx:
    image: nginx:alpine
    ports:
      - "443:443"
    volumes:
      - certs:/etc/nginx/certs:ro  # Mount the same volume as read-only
      - ./nginx.conf:/etc/nginx/conf.d/default.conf:ro
    depends_on:
      - zero
    restart: unless-stopped
```

Example nginx.conf:
```nginx
server {
    listen 443 ssl;
    server_name example.com;

    ssl_certificate /etc/nginx/certs/example.com.crt;
    ssl_certificate_key /etc/nginx/certs/example.com.key;

    # ... rest of your configuration ...
}
```
