BINARY_PATH = ./dist/cryptotimed
MAIN_FILE = ./src/main.go

build:
	go build -o $(BINARY_PATH) $(MAIN_FILE)

test:
	go test ./...

fmt:
	go fmt ./...

mod-tidy:
	go mod tidy
