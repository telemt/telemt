# syntax=docker/dockerfile:1

ARG TELEMT_REPOSITORY=telemt/telemt
ARG TELEMT_VERSION=latest

# ==========================
# Rust Builder (compiles from source, static musl binary)
# ==========================
FROM rust:1.88-bookworm AS builder

ARG TARGETARCH

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends musl-tools; \
    rm -rf /var/lib/apt/lists/*

# Determine the musl target triple based on the build architecture.
RUN set -eux; \
    case "${TARGETARCH:-amd64}" in \
        amd64) echo "x86_64-unknown-linux-musl" > /tmp/target.txt ;; \
        arm64) echo "aarch64-unknown-linux-musl" > /tmp/target.txt ;; \
        *) echo "Unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac

RUN rustup target add "$(cat /tmp/target.txt)"

WORKDIR /build

# Copy dependency manifests first for layer caching.
COPY Cargo.toml Cargo.lock ./
COPY .cargo .cargo/

# Create a dummy src/main.rs so cargo can fetch and compile dependencies
# without the full source tree. This layer is cached as long as
# Cargo.toml/Cargo.lock don't change.
RUN mkdir -p src && echo "fn main() {}" > src/main.rs && \
    cargo build --release --target "$(cat /tmp/target.txt)" || true

# Copy the actual source and build the real binary.
COPY src src
COPY benches benches

RUN touch src/main.rs && cargo build --release --target "$(cat /tmp/target.txt)"

# Place the binary at a fixed path so downstream stages can COPY it
# without knowing the target triple.
RUN cp "target/$(cat /tmp/target.txt)/release/telemt" /telemt-binary

# ==========================
# Minimal Image
# ==========================
FROM debian:12-slim AS minimal

ARG TARGETARCH
ARG TELEMT_REPOSITORY
ARG TELEMT_VERSION

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        binutils \
        ca-certificates; \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /telemt-binary /telemt
RUN strip --strip-unneeded /telemt || true

RUN --mount=type=bind,target=/tmp \
    mkdir -p /app && \
    if [ -f /tmp/config.toml ]; then \
        cp /tmp/config.toml /app/config.toml; \
    elif [ -f /tmp/config/config.toml ]; then \
        cp /tmp/config/config.toml /app/config.toml; \
    else \
        echo "No config.toml provided; creating empty config.toml for ENV overriding" && touch /app/config.toml; \
    fi

# ==========================
# Debug Image
# ==========================
FROM debian:12-slim AS debug

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        tzdata \
        curl \
        iproute2 \
        busybox; \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=minimal /telemt /app/telemt
COPY ./config/config.toml /app/config.toml

EXPOSE 443 9090 9091

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD ["/app/telemt", "healthcheck", "/app/config.toml", "--mode", "liveness"]

ENTRYPOINT ["/app/telemt"]
CMD ["config.toml"]

# ==========================
# Production Netfilter Profile
# ==========================
FROM debian:12-slim AS prod-netfilter

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        conntrack \
        nftables \
        iptables; \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=minimal /telemt /app/telemt
COPY --from=minimal /app/config.toml /app/config.toml

EXPOSE 443 9090 9091

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD ["/app/telemt", "healthcheck", "/app/config.toml", "--mode", "liveness"]

ENTRYPOINT ["/app/telemt"]
CMD ["config.toml"]

# ==========================
# Production Distroless on MUSL
# ==========================
FROM gcr.io/distroless/static-debian12 AS prod

WORKDIR /app

COPY --from=minimal /telemt /app/telemt
COPY --from=minimal /app/config.toml /app/config.toml

USER nonroot:nonroot

EXPOSE 443 9090 9091

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD ["/app/telemt", "healthcheck", "/app/config.toml", "--mode", "liveness"]

ENTRYPOINT ["/app/telemt"]
CMD ["config.toml"]
