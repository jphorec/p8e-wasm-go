package main

import (
	"github.com/provenance-io/p8e-wasm-go/cmd/p8e/command"
)

var rootCmd = command.RootCmd()

func init() {
	rootCmd.AddCommand(command.RunCmd())
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		panic(err)
	}
}
