# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a high-performance C++ reverse proxy server named "QUIC Reverse Proxy" with advanced security features. The project supports HTTP/1.0, HTTP/1.1, HTTP/2, HTTP/3 (QUIC), WebSockets, and modern TLS configurations with **always-enabled HTTP/3 QUIC and ECH support**.

## Build Commands

### Development Build
```bash
make clean && make
```

### Debug Build
```bash
make debug
```

### Production Build
```bash
make clean && make -j$(nproc)
```

### Docker Build
```bash
make docker
```

### Code Quality
```bash
make lint      # Run cppcheck static analysis
make format    # Format code with clang-format
```

### Installation
```bash
sudo make install    # Install as system service
sudo make uninstall  # Remove system service
```

## Project Architecture

### Core Components

1. **main.cpp** - Application entry point and configuration loading
2. **proxy_server.{h,cpp}** - Main server class handling HTTP and HTTPS listeners
3. **config.h** - Configuration management via environment variables
4. **tls_handler.{h,cpp}** - TLS/SSL configuration and security settings
5. **http_handler.{h,cpp}** - HTTP protocol handling, request parsing, and forwarding
6. **compression.{h,cpp}** - Multi-format compression (gzip, brotli, zstd, deflate)
7. **websocket_handler.{h,cpp}** - WebSocket upgrade and proxy functionality

### Security Features

- **TLS 1.2/1.3 only** with restricted cipher suites:
  - TLS 1.2: `ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305`
  - TLS 1.3: `TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256`
- **secp384r1 ECDH curve only**
- **TLS Early Data support** for TLS 1.3
- **ECH (Encrypted Client Hello)** support (always enabled)
- **XFF header calculation** - ignores client-provided XFF headers for security
- **HTTP to HTTPS redirection** on port 80

### Dependencies

- **OpenSSL 3.0+** for TLS/SSL support with ECH extensions (always enabled)
- **nghttp2** for HTTP/2 support
- **nghttp3** for HTTP/3 QUIC support (always enabled)
- **zlib** for gzip/deflate compression
- **Brotli** for Brotli compression
- **zstd** for Zstandard compression
- **ASIO** (header-only) for asynchronous networking

### Configuration

The application is configured entirely through environment variables:
- `BACKEND_HOST` - Target backend server (default: 127.0.0.1)
- `BACKEND_PORT` - Target backend port (default: 8080)
- `HTTP_PORT` - HTTP listen port (default: 80)
- `HTTPS_PORT` - HTTPS listen port (default: 443)
- `TLS_CERT_FILE` - TLS certificate path
- `TLS_KEY_FILE` - TLS private key path

### Supported Features

- **Multi-protocol**: HTTP/1.0, HTTP/1.1, HTTP/2, HTTP/3 (QUIC always enabled)
- **Advanced Security**: ECH (always enabled), TLS 1.2/1.3 only, restricted ciphers
- **Compression**: Automatic compression for text-based content types  
- **WebSocket**: Full WebSocket proxy with bidirectional data relay
- **Health Check**: `/_gwhealthz` endpoint for monitoring
- **Docker**: Multi-stage Dockerfile with HTTP/3 and ECH dependencies
- **SystemD**: Service file with security restrictions

## Development Workflow

### Making Changes
1. Modify source files as needed
2. Run `make format` to ensure consistent formatting
3. Run `make lint` to check for potential issues
4. Build and test with `make debug`
5. Test functionality thoroughly

### Testing
- Manual testing with curl commands (see README.md)
- Health check endpoint: `curl http://localhost/_gwhealthz`
- WebSocket testing with websocat
- Compression testing with Accept-Encoding headers

### Common Tasks
- **Add new feature**: Modify appropriate handler class and update headers
- **Update TLS config**: Modify `tls_handler.cpp` cipher/curve settings
- **Add compression type**: Update `compressible_types_` in `http_handler.h`
- **Change ports**: Update `config.h` defaults or use environment variables

## Important Notes

- The proxy requires root privileges to bind to ports 80/443
- All X-Forwarded headers are recalculated for security
- Only specific content types are compressed (see README.md)
- Backend connections are established per request (no connection pooling)
- WebSocket connections are full-duplex proxied to backend

## Deployment

### Docker Deployment
```bash
docker run -d --name quic-proxy -p 80:80 -p 443:443 \
  -e BACKEND_HOST=backend.internal \
  -v /path/to/certs:/etc/ssl/certs:ro \
  quic-proxy:v1.2.3
```

### System Service
```bash
sudo systemctl enable quic-proxy
sudo systemctl start quic-proxy
sudo journalctl -u quic-proxy -f
```
