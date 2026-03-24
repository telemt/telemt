ARG ALPINE_VERSION=3.23

# ==========================
# Main build
# ==========================
FROM rust:alpine${ALPINE_VERSION} AS build
WORKDIR /src
COPY . .
RUN cargo build --release --verbose

# ==========================
# Compressed build
# ==========================
FROM alpine:${ALPINE_VERSION} AS build-compressed
WORKDIR /src/target/release/
COPY --from=build /src/target/release/telemt .
RUN apk add --no-cache upx binutils \
 && ( strip --strip-unneeded ./telemt || true ) \
 && ( upx --best --lzma ./telemt || true )

# ==========================
# Production Image
# ==========================
FROM alpine:${ALPINE_VERSION} AS prod
WORKDIR /app
COPY --from=build-compressed /src/target/release/telemt /app/telemt
COPY config.toml /app/config.toml

USER nonroot:nonroot
EXPOSE 443 9090 9091
ENTRYPOINT ["/app/telemt"]
CMD ["config.toml"]

# ==========================
# Debug Image
# ==========================
FROM prod AS debug
USER root:root
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    curl \
    iproute2 \
    busybox
