.PHONY: all server agent web clean gen-grpc install-proto-deps

all: server agent web

# Install gRPC dependencies
install-proto-deps:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Generate gRPC code from proto files
gen-grpc: install-proto-deps
	protoc --go_out=./server/grpc/pb --go_opt=paths=source_relative \
		--go-grpc_out=./server/grpc/pb --go-grpc_opt=paths=source_relative \
		-I./server/grpc/protos \
		./server/grpc/protos/*.proto

# Server
server:
	@echo "Building server..."
	cd server && go build -o bin/sentinel-server ./cmd/server

# Agent
agent:
	@echo "Building agent..."
	cd agent && go build -o bin/sentinel-agent ./cmd/agent

# WebUI
web:
	@echo "Building webUI..."
	cd web && pnpm install
	cd web && pnpm build

# Run server (for dev)
run-server:
	cd server && go run ./cmd/server

# Run agent (for dev)
run-agent:
	cd agent && go run ./cmd/agent

# Run webUI
run-web:
	cd web && pnpm dev

# Clean binaries
clean:
	@echo "Cleaning binaries..."
	rm -rf server/bin/*
	rm -rf agent/bin/*

# Clean generated gRPC code
clean-grpc:
	rm -f server/grpc/pb/*.go
