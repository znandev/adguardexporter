FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS build
WORKDIR /app

# Tambahkan tools build
RUN apk add --no-cache ca-certificates git

# Copy semua source code ke container
COPY . .

# Build biner static
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o adguard-exporter .

# Tahap ambil certs
FROM --platform=$BUILDPLATFORM alpine:3.22.1 AS certs
RUN apk add --no-cache ca-certificates

# Final image
FROM scratch
WORKDIR /

COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /app/adguard-exporter /adguard-exporter
USER 65532:65532

ENTRYPOINT ["/adguard-exporter"]
