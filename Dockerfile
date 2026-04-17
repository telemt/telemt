# syntax=docker/dockerfile:1

ARG TELEMT_REPOSITORY=telemt/telemt
ARG TELEMT_VERSION=latest

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
        ca-certificates \
        curl \
        tar; \
    rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    case "${TARGETARCH}" in \
        amd64) ASSET="telemt-x86_64-linux-musl.tar.gz" ;; \
        arm64) ASSET="telemt-aarch64-linux-musl.tar.gz" ;; \
        *) echo "Unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    VERSION="${TELEMT_VERSION#refs/tags/}"; \
    if [ -z "${VERSION}" ] || [ "${VERSION}" = "latest" ]; then \
        BASE_URL="https://github.com/${TELEMT_REPOSITORY}/releases/latest/download"; \
    else \
        BASE_URL="https://github.com/${TELEMT_REPOSITORY}/releases/download/${VERSION}"; \
    fi; \
    curl -fL \
        --retry 5 \
        --retry-delay 3 \
        --connect-timeout 10 \
        --max-time 120 \
        -o "/tmp/${ASSET}" \
        "${BASE_URL}/${ASSET}"; \
    curl -fL \
        --retry 5 \
        --retry-delay 3 \
        --connect-timeout 10 \
        --max-time 120 \
        -o "/tmp/${ASSET}.sha256" \
        "${BASE_URL}/${ASSET}.sha256"; \
    cd /tmp; \
    sha256sum -c "${ASSET}.sha256"; \
    tar -xzf "${ASSET}" -C /tmp; \
    test -f /tmp/telemt; \
    install -m 0755 /tmp/telemt /telemt; \
    strip --strip-unneeded /telemt || true; \
    rm -f "/tmp/${ASSET}" "/tmp/${ASSET}.sha256" /tmp/telemt

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
COPY config.toml /app/config.toml

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
COPY config.toml /app/config.toml

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
COPY config.toml /app/config.toml

USER nonroot:nonroot

EXPOSE 443 9090 9091

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD ["/app/telemt", "healthcheck", "/app/config.toml", "--mode", "liveness"]

ENTRYPOINT ["/app/telemt"]
CMD ["config.toml"]
