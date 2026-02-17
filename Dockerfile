# syntax=docker/dockerfile:1.4

# Zentinel Rate Limit Agent Container Image
#
# Targets:
#   - prebuilt: For CI with pre-built binaries

################################################################################
# Pre-built binary stage (for CI builds)
################################################################################
FROM gcr.io/distroless/cc-debian12:nonroot AS prebuilt

COPY zentinel-ratelimit-agent /zentinel-ratelimit-agent

LABEL org.opencontainers.image.title="Zentinel Rate Limit Agent" \
      org.opencontainers.image.description="Zentinel Rate Limit Agent for Zentinel reverse proxy" \
      org.opencontainers.image.vendor="Raskell" \
      org.opencontainers.image.source="https://github.com/zentinelproxy/zentinel-agent-ratelimit"

ENV RUST_LOG=info,zentinel_ratelimit_agent=debug \
    SOCKET_PATH=/var/run/zentinel/ratelimit.sock

USER nonroot:nonroot

ENTRYPOINT ["/zentinel-ratelimit-agent"]
