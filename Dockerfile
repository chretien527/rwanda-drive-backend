# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /app

# Install git and ca-certificates (needed for go modules)
RUN apk add --no-cache git ca-certificates

# Copy Go module files and source code first
COPY . .

# Download dependencies and tidy based on actual source
RUN go mod tidy && go mod download

# Build the application
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o /app/bin/api ./cmd/api

# Final stage
FROM alpine:latest

# Install ca-certificates for HTTPS calls
RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy pre-built binary from builder stage
COPY --from=builder /app/bin/api .

# Copy .env.example as template (in production, use proper secrets management)
COPY .env.example .env

# Expose port
EXPOSE 8080

# Run the application
CMD ["./api"]
