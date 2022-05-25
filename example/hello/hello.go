package main

import (
	"github.com/provenance-io/p8e-wasm-go/pkg/wasm"
	"github.com/provenance-io/p8e-wasm-go/pkg/wasm/runtime"
)

type helloContract struct {
}

func (h helloContract) HelloWorld(inputs []wasm.P8EFact) (outputs []wasm.P8EFact) {
	panic("implement me")
}

func New() interface{} {
	return &helloContract{}
}

func main() {
	runtime.Start(New)
}
