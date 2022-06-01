package command

import (
	"C"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/spf13/cobra"
	"github.com/wasmerio/wasmer-go/wasmer"
)
import "bytes"

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
			log.Println("Exports are:")
			for _, exp := range module.Exports() {
				log.Printf("exported:%s", exp.Name())
			}

			importObj := wasmer.NewImportObject()
			instance, err := wasmer.NewInstance(module, importObj)
			if err != nil {
				return err
			}
			log.Printf("%+v\n", instance)

			err = greet(instance, "test")
			if err != nil {
				log.Printf("Error greeting: %v", err)
			}
			err = add(instance)
			if err != nil {
				log.Printf("Error adding: %v", err)
			}

			return nil
		},
	}
}

func greet(instance *wasmer.Instance, name string) error {
	greet, err := instance.Exports.GetFunction("greet")
	if err != nil {
		return err
	}

	memory, err := instance.Exports.GetMemory("memory")
	if err != nil {
		return err
	}
	data := memory.Data()
	copy(data, name)
	fmt.Printf("about to greet: %s\n", string(data[:len(name)]))

	result, err := greet(0)
	if err != nil {
		return err
	}

	data = memory.Data()

	fmt.Printf("result pointer: %d\n", result.(int32))
	idx := result.(int32)
	idxNull := int32(bytes.IndexByte(data[idx:], byte(0)))
	fmt.Printf("greet result: %s\n", string(data[idx:idx+idxNull]))

	return nil
}

func add(instance *wasmer.Instance) error {
	doAdd, err := instance.Exports.GetFunction("add")
	if err != nil {
		return err
	}

	result, err := doAdd(1, 2)
	if err != nil {
		return err
	}
	fmt.Printf("add result: %+v\n", result)

	return nil
}
