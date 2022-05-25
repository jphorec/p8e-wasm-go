package command

import (
	"C"
	"fmt"
	"github.com/spf13/cobra"
	"github.com/wasmerio/wasmer-go/wasmer"
	"io/ioutil"
	"log"
)

func RunCmd() *cobra.Command {
	return &cobra.Command{
		Use:  "run",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			wasmBytes, err := ioutil.ReadFile(args[0])
			if err != nil {
				return err
			}

			engine := wasmer.NewEngine()
			store := wasmer.NewStore(engine)
			module, err := wasmer.NewModule(store, wasmBytes)
			if err != nil {
				return err
			}
			for export, _ := range module.Exports() {
				log.Printf("exported:%+v", export)
			}

			importObj := wasmer.NewImportObject()
			instance, err := wasmer.NewInstance(module, importObj)
			if err != nil {
				return err
			}

			log.Printf("%+v\n", instance)
			greet, err := instance.Exports.GetFunction("greet")
			if err != nil {
				return err
			}
			result, err := greet(C.CString("test"))
			if err != nil {
				return err
			}
			fmt.Printf("%+v\n", result)

			return nil
		},
	}
}
