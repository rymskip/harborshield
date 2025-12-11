# Build stage
FROM rust:slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy manifest files
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src ./src

# Build the application in release mode
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    nftables \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user (but the app needs CAP_NET_ADMIN)
RUN useradd -m -u 1000 harborshield

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/target/release/harborshield /usr/local/bin/harborshield

# Create data directory
RUN mkdir -p /data && chown harborshield:harborshield /data

# The application needs CAP_NET_ADMIN to manage nftables
# This is added via docker-compose.yml

USER harborshield

# Health check endpoint
EXPOSE 8080

ENTRYPOINT ["harborshield"]
CMD ["--data-dir", "/data", "--health-server", "0.0.0.0:8080"]