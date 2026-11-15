# Build stage
FROM rust:1.99.1-slim-trixie AS builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY xtask/Cargo.toml ./xtask/Cargo.toml
COPY xtask/src ./xtask/src
COPY src ./src
COPY migrations ./migrations
COPY .sqlx ./.sqlx

# Query macros check against the committed .sqlx cache instead of a live database.
ENV SQLX_OFFLINE=true
RUN cargo build --release --bin harborshield

# Runtime stage
FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    nftables \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1000 harborshield

WORKDIR /app

COPY --from=builder /app/target/release/harborshield /usr/local/bin/harborshield

RUN mkdir -p /data && chown harborshield:harborshield /data

# The application needs CAP_NET_ADMIN to manage nftables
# This is added via docker-compose.yml

USER harborshield

# Health check endpoint
EXPOSE 8080

ENTRYPOINT ["harborshield"]
CMD ["--data-dir", "/data", "--health-server", "0.0.0.0:8080"]
