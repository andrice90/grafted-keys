.PHONY: run build tidy test docker up down clean

# Local dev: serves on :8080, data in ./data, backups in ./backups
run:
	GRAFTED_DATA_DIR=./data GRAFTED_BACKUP_DIR=./backups GRAFTED_SECURE_COOKIE=0 \
		go run ./cmd/grafted

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o grafted ./cmd/grafted

tidy:
	go mod tidy

test:
	go test ./...

docker:
	docker build -t grafted-secrets:latest .

up:
	docker compose up -d --build

down:
	docker compose down

clean:
	rm -rf grafted dist data backups
