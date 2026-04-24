# Build Stage - Native Node
FROM rust:stable-slim-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
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
RUN cargo build --release -p hegemon-node --bin hegemon-node --no-default-features

# Runtime Stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
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

# Default command - development mode
CMD ["--dev", "--tmp", "--rpc-cors=all", "--rpc-external"]
