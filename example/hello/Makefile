SRC = $(shell find . -type f -name '*.go')

.PHONY: build
build: $(SRC)
	GOOS=js GOARCH=wasm go build -o hello.wasm

run: hello.wasm
	$(shell go env GOROOT)/misc/wasm/go_js_wasm_exec hello.wasm
