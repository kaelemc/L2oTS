FROM golang:1.24.5-bookworm AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o /out/tsl2 ./main.go

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables iproute2 iputils-ping ca-certificates curl

RUN mkdir -p --mode=0755 /usr/share/keyrings

RUN curl -fsSL https://pkgs.tailscale.com/stable/debian/bookworm.noarmor.gpg | tee /usr/share/keyrings/tailscale-archive-keyring.gpg >/dev/null
RUN curl -fsSL https://pkgs.tailscale.com/stable/debian/bookworm.tailscale-keyring.list | tee /etc/apt/sources.list.d/tailscale.list

RUN apt-get update && apt-get install -y tailscale && rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/tsl2 /usr/local/bin/tsl2
ENTRYPOINT ["/usr/local/bin/tsl2"]