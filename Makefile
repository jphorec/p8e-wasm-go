TARGET = p8e
GO     = go
SRC    = $(shell find . -type f -name '*.go')

all: $(TARGET)

$(TARGET): build/$(TARGET)

build/$(TARGET): $(SRC)
	$(GO) build -o build/ ./cmd/$(TARGET)
