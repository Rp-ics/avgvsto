# AVGVSTO Server — Multi-stage Docker build per Fly.io
FROM rust:1.81-alpine AS builder

RUN apk add --no-cache musl-dev pkgconfig openssl-dev

WORKDIR /app
COPY . .

RUN cargo build --release --package avgvsto-server

FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata libgcc

COPY --from=builder /app/target/release/avgvsto-server /usr/local/bin/avgvsto-server

RUN addgroup -S avgvsto && adduser -S avgvsto -G avgvsto

USER avgvsto
EXPOSE 8080

ENTRYPOINT ["avgvsto-server"]
