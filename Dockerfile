# syntax=docker/dockerfile:1.4

# Sentinel Rate Limit Agent Container Image
#
# Targets:
#   - prebuilt: For CI with pre-built binaries

################################################################################
# Pre-built binary stage (for CI builds)
################################################################################
FROM gcr.io/distroless/cc-debian12:nonroot AS prebuilt

COPY sentinel-ratelimit-agent /sentinel-ratelimit-agent

LABEL org.opencontainers.image.title="Sentinel Rate Limit Agent" \
      org.opencontainers.image.description="Sentinel Rate Limit Agent for Sentinel reverse proxy" \
      org.opencontainers.image.vendor="Raskell" \
      org.opencontainers.image.source="https://github.com/raskell-io/sentinel-agent-ratelimit"

ENV RUST_LOG=info,sentinel_ratelimit_agent=debug \
    SOCKET_PATH=/var/run/sentinel/ratelimit.sock

USER nonroot:nonroot

ENTRYPOINT ["/sentinel-ratelimit-agent"]
