# Build Stage
FROM rust:1.81-slim-bookworm as builder

# Install Node.js for dashboard build
RUN apt-get update && apt-get install -y nodejs npm pkg-config libssl-dev git clang

WORKDIR /app

# Copy source code
COPY . .

# Build Dashboard
RUN ./scripts/build_dashboard.sh

# Build Node Binary
RUN cargo build --release -p node

# Runtime Stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/node /usr/local/bin/node

# Create data directory
RUN mkdir -p /data

# Expose ports
EXPOSE 8080 9000

# Entrypoint
ENTRYPOINT ["node"]
ENV NODE_WALLET_PASSPHRASE=changeme
CMD [
  "--db-path", "/data/node.db",
  "--wallet-store", "/data/wallet.db",
  "--wallet-auto-create",
  "--api-addr", "0.0.0.0:8080",
  "--p2p-addr", "0.0.0.0:9000"
]
