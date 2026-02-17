# zentinel-agent-ratelimit

Token bucket rate limiting agent for [Zentinel](https://github.com/zentinelproxy/zentinel) reverse proxy.

## Features

- Token bucket rate limiting algorithm
- Per-client rate limits (by IP, header, or custom key)
- Configurable burst allowance
- Hot-reloadable configuration
- Prometheus metrics export

## Installation

### From crates.io

```bash
cargo install zentinel-agent-ratelimit
```

### From source

```bash
git clone https://github.com/zentinelproxy/zentinel-agent-ratelimit
cd zentinel-agent-ratelimit
cargo build --release
```

## Usage

```bash
zentinel-ratelimit-agent --socket /var/run/zentinel/ratelimit.sock
```

### Command Line Options

| Option | Environment Variable | Description | Default |
|--------|---------------------|-------------|---------|
| `--socket` | `AGENT_SOCKET` | Unix socket path | `/tmp/zentinel-ratelimit.sock` |
| `--config` | `RATELIMIT_CONFIG` | Configuration file path | - |
| `--default-rps` | `RATELIMIT_DEFAULT_RPS` | Default requests per second | `100` |
| `--default-burst` | `RATELIMIT_DEFAULT_BURST` | Default burst size | `10` |
| `--log-level` | `RUST_LOG` | Log level | `info` |

## Configuration

### Configuration File (YAML)

```yaml
# Global defaults
defaults:
  requests_per_second: 100
  burst_size: 10

# Per-route limits
routes:
  "/api/v1/upload":
    requests_per_second: 10
    burst_size: 2
  "/api/v1/search":
    requests_per_second: 50
    burst_size: 5

# Key extraction (what to rate limit by)
key_extraction:
  type: "ip"  # ip, header, or composite
  # header: "X-API-Key"  # if type is header
```

### Zentinel Proxy Configuration

Add to your Zentinel `config.kdl`:

```kdl
agents {
    agent "ratelimit" {
        type "custom"
        transport "unix_socket" {
            path "/var/run/zentinel/ratelimit.sock"
        }
        events ["request_headers"]
        timeout-ms 50
        failure-mode "open"
    }
}

routes {
    route "api" {
        matches { path-prefix "/api" }
        upstream "backend"
        agents ["ratelimit"]
    }
}
```

## Metrics

The agent exposes Prometheus metrics on the configured metrics port:

| Metric | Type | Description |
|--------|------|-------------|
| `ratelimit_requests_total` | Counter | Total requests processed |
| `ratelimit_limited_total` | Counter | Total requests rate limited |
| `ratelimit_allowed_total` | Counter | Total requests allowed |
| `ratelimit_bucket_tokens` | Gauge | Current tokens in bucket (by key) |

## Response Headers

When a request is rate limited, the agent adds these headers:

- `X-RateLimit-Limit`: Maximum requests per second
- `X-RateLimit-Remaining`: Remaining requests in current window
- `X-RateLimit-Reset`: Unix timestamp when the limit resets
- `Retry-After`: Seconds until the client can retry (on 429)

## Development

```bash
# Run with debug logging
RUST_LOG=debug cargo run -- --socket /tmp/test.sock

# Run tests
cargo test

# Run benchmarks
cargo bench
```

## License

Apache-2.0
