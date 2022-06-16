TARGET = p8e
GO     = go
SRC    = $(shell find . -type f -name '*.go')

all: $(TARGET)

$(TARGET): build/$(TARGET)

build/$(TARGET): $(SRC)
	$(GO) build -o build/ ./cmd/$(TARGET)

proto:
	docker run --rm -v `pwd`/example/hello-rust/proto:/proto -v `pwd`/cmd/p8e/command/hello:/build:rw -w='/' --entrypoint=protoc namely/protoc -I./proto -I/opt/include --gogo_out=./build --gogo_opt=paths=source_relative hello.proto