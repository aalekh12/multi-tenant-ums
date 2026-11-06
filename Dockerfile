# Build stage
FROM golang:1.26-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git

COPY . .

RUN go mod download

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /bin/api ./cmd/api
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /bin/seed ./cmd/seed

# Production stage
FROM alpine:3.19

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

COPY --from=builder /bin/api /app/api
COPY --from=builder /bin/seed /app/seed
COPY --from=builder /app/migrations /app/migrations
COPY --from=builder /app/docs /app/docs

EXPOSE 8080

ENTRYPOINT ["/app/api"]

