FROM golang:1.27-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /prox-em-all ./cmd/prox-em-all

FROM alpine:3.24

LABEL org.opencontainers.image.source="https://github.com/VirgileD/prox-em-all"

RUN apk add --no-cache iptables
COPY --from=build /prox-em-all /usr/local/bin/prox-em-all

ENTRYPOINT ["prox-em-all"]
CMD ["-c", "/etc/prox-em-all/config.yaml"]
