# ==========================
# Stage 1: Build
# ==========================
FROM rust:1.88-slim-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY Cargo.toml Cargo.lock* ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs && \
    cargo build --release 2>/dev/null || true && \
    rm -rf src

COPY . .
RUN cargo build --release && strip target/release/telemt

# ==========================
# Stage 2: Runtime
# ==========================
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -r -s /usr/sbin/nologin telemt

WORKDIR /app

COPY --from=builder /build/target/release/telemt /app/telemt
COPY config.toml /app/config.toml

RUN chown -R telemt:telemt /app
USER telemt

EXPOSE 443
EXPOSE 9090

ENTRYPOINT ["/app/telemt"]
CMD ["config.toml"]
