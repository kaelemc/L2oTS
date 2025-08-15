FROM --platform=$BUILDPLATFORM golang:1.24.5-bookworm AS builder
ARG TARGETARCH
ARG TARGETOS
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o /out/tsl2 ./main.go

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables iproute2 iputils-ping ca-certificates curl

COPY --from=builder /out/tsl2 /usr/local/bin/tsl2
ENTRYPOINT ["/usr/local/bin/tsl2"]