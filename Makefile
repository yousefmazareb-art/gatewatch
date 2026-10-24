.PHONY: build test run docker
build:
$\tCGO_ENABLED=1 go build -o bin/gatewatch ./cmd/gatewatch
test:
$\tgo test ./internal/tracker/... ./internal/tlsfp/...
run: build
$\tsudo ./bin/gatewatch -iface eth0
docker:
$\tdocker compose -f deploy/docker-compose.yml up -d --build
