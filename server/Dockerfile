# Use multi-stage build to keep final image small
FROM golang:1.25.4-alpine AS builder

# Install git and other build dependencies
RUN apk add --no-cache git ca-certificates gcc musl-dev

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o sentinel-server ./cmd/server/main.go

# Final stage
FROM alpine:latest

# Install ca-certificates for TLS connections
RUN apk --no-cache add ca-certificates

# Create a non-root user
RUN adduser -D -s /bin/sh sentinel

# Set working directory
WORKDIR /home/sentinel

# Copy the binary from builder stage
COPY --from=builder /app/sentinel-server .

# Make the binary executable
RUN chmod +x sentinel-server

# Change ownership to sentinel user
RUN chown -R sentinel:sentinel /home/sentinel

# Switch to sentinel user
USER sentinel

# Expose HTTP and gRPC ports
EXPOSE 3000
EXPOSE 50051

# Command to run the application
CMD ["./sentinel-server"]