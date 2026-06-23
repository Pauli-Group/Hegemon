# Build Stage - Native Node
FROM rust:1-slim-bookworm@sha256:c8a94a78f67ec8c4d474ec7f71e0720f21eb7e584e158daec0874cafa7c30e4d AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    git \
    clang \
    cmake \
    protobuf-compiler \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy source code
COPY . .

# Build native node binary
RUN cargo build --locked --release -p hegemon-node --bin hegemon-node --no-default-features

# Runtime Stage
FROM debian:bookworm-slim@sha256:96e378d7e6531ac9a15ad505478fcc2e69f371b10f5cdf87857c4b8188404716

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    curl \
    jq \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the native node binary
COPY --from=builder /app/target/release/hegemon-node /usr/local/bin/hegemon-node

# Create data directory
RUN mkdir -p /data /config /keys

# Health check endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:9944/health || exit 1

# Expose ports
# 30333 - P2P
# 9944  - RPC (HTTP/WS)
EXPOSE 30333 9944

# Default environment
ENV RUST_LOG=info,hegemon=debug
ENV RUST_BACKTRACE=1

# Entrypoint
ENTRYPOINT ["hegemon-node"]

# Default command - development mode with loopback RPC.
CMD ["--dev", "--tmp"]
