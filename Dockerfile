FROM golang:1.16.5-alpine AS build-env
RUN GO111MODULE=on go get -v github.com/projectdiscovery/mapcidr/cmd/mapcidr

FROM alpine:latest
COPY --from=build-env /go/bin/mapcidr /usr/local/bin/mapcidr
ENTRYPOINT ["mapcidr"]
