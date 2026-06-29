# syntax=docker/dockerfile:1.7

ARG RUST_VERSION=1.88
ARG DEBIAN_VERSION=bookworm

# ==========================
# Build TeleMT from current sources
# ==========================
FROM --platform=$TARGETPLATFORM rust:${RUST_VERSION}-${DEBIAN_VERSION} AS build

ARG TARGETARCH
ARG PROFILE=release
ARG CARGO_FEATURES=""
ARG CARGO_EXTRA_ARGS=""

WORKDIR /src

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        pkg-config \
        build-essential \
        musl-tools \
        clang \
        lld \
        binutils; \
    rm -rf /var/lib/apt/lists/*; \
    case "${TARGETARCH}" in \
        amd64) RUST_TARGET="x86_64-unknown-linux-musl" ;; \
        arm64) RUST_TARGET="aarch64-unknown-linux-musl" ;; \
        *) echo "Unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    rustup target add "${RUST_TARGET}"

COPY . .

RUN set -eux; \
    case "${TARGETARCH}" in \
        amd64) RUST_TARGET="x86_64-unknown-linux-musl" ;; \
        arm64) RUST_TARGET="aarch64-unknown-linux-musl" ;; \
        *) echo "Unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    if [ -n "${CARGO_FEATURES}" ]; then \
        cargo build --locked --profile "${PROFILE}" --target "${RUST_TARGET}" --features "${CARGO_FEATURES}" ${CARGO_EXTRA_ARGS}; \
    else \
        cargo build --locked --profile "${PROFILE}" --target "${RUST_TARGET}" ${CARGO_EXTRA_ARGS}; \
    fi; \
    BIN_PATH="target/${RUST_TARGET}/${PROFILE}/telemt"; \
    test -f "${BIN_PATH}"; \
    install -m 0755 "${BIN_PATH}" /telemt; \
    strip --strip-unneeded /telemt || true; \
    /telemt --help >/dev/null || true

# ==========================
# Config stage
# ==========================
FROM debian:12-slim AS config

WORKDIR /app

RUN --mount=type=bind,target=/tmp/context,source=. \
    set -eux; \
    if [ -f /tmp/context/config.toml ]; then \
        cp /tmp/context/config.toml /app/config.toml; \
    elif [ -f /tmp/context/config/config.toml ]; then \
        cp /tmp/context/config/config.toml /app/config.toml; \
    else \
        echo "Config file not found: expected ./config.toml or ./config/config.toml" >&2; \
        exit 1; \
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

COPY --from=build /telemt /app/telemt
COPY --from=config /app/config.toml /app/config.toml

EXPOSE 443 9090 9091 9092

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["/app/telemt", "healthcheck", "/app/config.toml", "--mode", "liveness"]

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

COPY --from=build /telemt /app/telemt
COPY --from=config /app/config.toml /app/config.toml

EXPOSE 443 9090 9091 9092

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["/app/telemt", "healthcheck", "/app/config.toml", "--mode", "liveness"]

ENTRYPOINT ["/app/telemt"]
CMD ["config.toml"]

# ==========================
# Production Distroless on MUSL
# ==========================
FROM gcr.io/distroless/static-debian12 AS prod

WORKDIR /app

COPY --from=build /telemt /app/telemt
COPY --from=config /app/config.toml /app/config.toml

USER nonroot:nonroot

EXPOSE 443 9090 9091 9092

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["/app/telemt", "healthcheck", "/app/config.toml", "--mode", "liveness"]

ENTRYPOINT ["/app/telemt"]
CMD ["config.toml"]
