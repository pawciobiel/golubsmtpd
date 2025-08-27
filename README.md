# golubsmtpd

A small, fast, and secure SMTP server written in Go with minimal external dependencies.

## Features

- **Authentication**: SMTP AUTH LOGIN and PLAIN mechanisms
- **Plugin System**: Configurable authentication backends (file, memory)
- **Email Validation**: Configurable validation pipeline (basic, extended, DNS)
- **Security**: rDNS and DNSBL checking, connection limits, rate limiting
- **Lock-free Design**: High-performance concurrent connection handling
- **RFC Compliance**: Standards-compliant SMTP implementation

## Quick Start

### Build
```bash
go build ./cmd/golubsmtpd
```

### Test
```bash
go test ./...
```

### Run
```bash
./golubsmtpd -config config.yaml
```

### Test SMTP Connection
```bash
echo -e "EHLO test.example.com\nQUIT" | nc 127.0.0.1 2525
```

## Configuration

The server uses YAML configuration with support for:

- **Authentication plugins**: `file` or `memory` based user storage
- **Email validation**: `["basic"]`, `["basic", "extended"]`, `["basic", "extended", "dns_mx"]`
- **Security features**: rDNS lookup, DNSBL checking
- **Connection limits**: Total and per-IP connection limits

Example minimal config:
```yaml
server:
  bind: "127.0.0.1"
  port: 2525
  email_validation: ["basic"]

auth:
  plugin: "memory"
  plugins:
    memory:
      users:
        - username: "test"
          password: "pass"
```

## Development

- **Go Version**: 1.25.0
- **Dependencies**: Only `gopkg.in/yaml.v3` for configuration
- **License**: GPL/GNU

## TODO

- IPv6 support for DNSBL checking and connection handling
- TLS/STARTTLS support
- Local delivery and Maildir storage implementation
- Mail relay for authenticated users
- Fix readMessageData to check input size before allocating buffer (DoS protection)
- Improve command handling security with input validation and rate limiting
- Additional authentication methods (CRAM-MD5)
- Performance metrics and monitoring
- Hot-reload configuration