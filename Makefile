.PHONY: up down migrate-up migrate-down seed run test test-integration cover swagger lint bench

DB_URL ?= postgres://postgres:postgrespassword@localhost:5432/usermgmt?sslmode=disable
MIGRATE_IMAGE ?= migrate/migrate:v4.17.0

up:
	docker compose up -d

down:
	docker compose down -v

migrate-up:
	docker run --rm -v $(CURDIR)/migrations:/migrations --network host $(MIGRATE_IMAGE) -path=/migrations -database "$(DB_URL)" up

migrate-down:
	docker run --rm -v $(CURDIR)/migrations:/migrations --network host $(MIGRATE_IMAGE) -path=/migrations -database "$(DB_URL)" down 1

seed:
	go run ./cmd/seed

run:
	go run ./cmd/api

test:
	go test -v -race ./internal/...

test-integration:
	go test -v -tags=integration ./test/integration/...

cover:
	go test -coverprofile=coverage.out ./internal/...
	go tool cover -func=coverage.out

swagger:
	@which swag > /dev/null || go install github.com/swaggo/swag/cmd/swag@v1.16.3
	swag init -g cmd/api/main.go -o docs --outputTypes yaml,json

lint:
	@which golangci-lint > /dev/null || go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.59.1
	golangci-lint run ./...

bench:
	go test -bench=. -benchmem ./...

