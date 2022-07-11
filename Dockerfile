FROM golang:1.18-alpine3.16 as builder

ENV CGO_ENABLED=0

COPY . /go/src/github.com/NectGmbH/cert-monitor-controller
WORKDIR /go/src/github.com/NectGmbH/cert-monitor-controller

RUN set -ex \
 && apk add --update git \
 && go install \
      -ldflags "-X main.version=$(git describe --tags --always || echo dev)" \
      -mod=readonly \
      -modcacherw \
      -trimpath


FROM alpine:3.16

LABEL maintainer "Knut Ahlers <ka@nect.com>"

RUN set -ex \
 && addgroup -g 1000 certmon \
 && adduser -D -G certmon -H -u 1000 certmon \
 && apk --no-cache add \
      ca-certificates

COPY --from=builder /go/bin/cert-monitor-controller /usr/local/bin/cert-monitor-controller

EXPOSE 3000

USER certmon

ENTRYPOINT ["/usr/local/bin/cert-monitor-controller"]
CMD ["--"]

# vim: set ft=Dockerfile:
