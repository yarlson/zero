.PHONY: proto
proto:
	@echo "Generating protobuf code..."
	protoc \
		--go_out=. \
		--go_opt=paths=source_relative \
		--go-grpc_out=require_unimplemented_servers=false:. \
		--go-grpc_opt=paths=source_relative \
		cluster/proto/cluster.proto

.PHONY: deps
deps:
	@echo "Installing protoc dependencies..."
	go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.32.0
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.3.0 