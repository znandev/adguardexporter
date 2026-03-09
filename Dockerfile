FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
WORKDIR /app

RUN apk add --no-cache ca-certificates git

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -ldflags="-s -w" -o adguard-exporter .

FROM alpine:3.20 AS certs
RUN apk add --no-cache ca-certificates

FROM scratch
WORKDIR /

COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /app/adguard-exporter /adguard-exporter
COPY --from=build /app/GeoLite2-City.mmdb /GeoLite2-City.mmdb

USER 65532:65532

EXPOSE 9200

ENTRYPOINT ["/adguard-exporter"]
