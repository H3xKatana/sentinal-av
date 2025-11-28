# Use a multi-stage build to keep the final image small
FROM golang:1.25.4-alpine AS builder

# Install build dependencies for YARA
RUN apk add --no-cache \
    gcc \
    musl-dev \
    pkgconfig \
    git

# Install YARA library development files
RUN apk add --no-cache yara-dev yara

# Set the working directory inside the container
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code
COPY . .

# Build the agent binary
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o sentinel-agent ./cmd/agent

# Use a minimal base image for the final stage
FROM alpine:latest

# Install YARA runtime library
RUN apk --no-cache add yara

# Create a non-root user
RUN adduser -D -s /bin/sh agent

# Create app directory
WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /app/sentinel-agent .

# Make the binary executable
RUN chmod +x sentinel-agent

# Change ownership to the agent user
RUN chown agent:agent sentinel-agent

# Switch to non-root user
USER agent

# Default command - agent will need environment variables like VT_KEY and SERVER_URL
CMD ["./sentinel-agent"]