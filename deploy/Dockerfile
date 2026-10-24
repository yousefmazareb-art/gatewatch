# Build stage (libpcap needs CGO)
FROM golang:1.22-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends libpcap-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -o /out/gatewatch ./cmd/gatewatch

# Runtime stage
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends libpcap0.8 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/gatewatch /usr/local/bin/gatewatch
ENTRYPOINT ["gatewatch"]
