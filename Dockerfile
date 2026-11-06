FROM --platform=$BUILDPLATFORM alpine:3.24 AS certs
RUN apk add --no-cache ca-certificates

FROM scratch
WORKDIR /

COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

ARG TARGETPLATFORM
COPY ${TARGETPLATFORM}/adguard-exporter /adguard-exporter

USER 65532:65532

EXPOSE 9617

ENTRYPOINT ["/adguard-exporter"]
