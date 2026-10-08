FROM alpine:latest

LABEL org.opencontainers.image.authors="ProjectDiscovery"
LABEL org.opencontainers.image.description="A utility program to perform multiple operations for a given subnet/CIDR range."
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.title="mapcidr"
LABEL org.opencontainers.image.url="https://github.com/projectdiscovery/mapcidr"

RUN apk -U upgrade --no-cache \
    && apk add --no-cache bind-tools ca-certificates

ARG TARGETPLATFORM
COPY $TARGETPLATFORM/mapcidr /usr/local/bin/

ENTRYPOINT ["mapcidr"]
