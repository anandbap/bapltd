# Multi-stage Dockerfile for BAP Control Plane on Render / Cloud
FROM golang:1.25-alpine AS builder

WORKDIR /app

# Copy dependency manifests
COPY bap-controlplane/go.mod bap-controlplane/go.sum* ./bap-controlplane/
WORKDIR /app/bap-controlplane
ENV GOTOOLCHAIN=auto
RUN go mod download

# Copy full repository
WORKDIR /app
COPY . .

# Compile bapcontrolplane statically with CGO disabled (pure Go SQLite)
WORKDIR /app/bap-controlplane
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /app/bapcontrolplane ./cmd/server

# Minimal production runtime image
FROM alpine:3.20

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/bapcontrolplane /app/bapcontrolplane

# Copy Cedar policies and schemas for runtime evaluation
COPY bap-edge/policy.cedar /app/bap-edge/policy.cedar
COPY bap-edge/schema.json /app/bap-edge/schema.json

# Default environment settings
ENV BAP_MODE=prod
ENV PORT=8080
ENV BAP_DB_PATH=/app/bap-controlplane.db

EXPOSE 8080

CMD ["/app/bapcontrolplane"]
