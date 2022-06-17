package command

import (
	"C"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/spf13/cobra"
	"github.com/wasmerio/wasmer-go/wasmer"

	"github.com/gogo/protobuf/proto"
	"github.com/provenance-io/p8e-wasm-go/cmd/p8e/command/hello"
)
import (
	"encoding/binary"
	"encoding/json"
	"strings"
)

type RecordType string

const (
	Proposed RecordType = "Proposed"
	Existing RecordType = "Existing"
)

type P8eFunctionParamter struct {
	RecordType RecordType `json:"record_type"`
	Name       string     `json:"name"`
	Optional   bool       `json:"optional"`
	Type       string     `json:"type"`
}

type P8eFunction struct {
	Name       string                `json:"name"`
	Parameters []P8eFunctionParamter `json:"parameters"`
}

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
			p8eFunctions := make([]string, len(module.Exports()))
			for _, exp := range module.Exports() {
				log.Printf("exported:%s", exp.Name())
				if strings.HasPrefix(exp.Name(), "__P8E_FUNCTION_") && !strings.HasPrefix(exp.Name(), "__P8E_FUNCTION_LENGTH_") {
					p8eFunctions = append(p8eFunctions[:], exp.Name())
				}
			}

			importObj := wasmer.NewImportObject()
			instance, err := wasmer.NewInstance(module, importObj)
			if err != nil {
				return err
			}

			log.Printf("p8e functions are %+v", p8eFunctions)
			p8eTable, err := instance.Exports.GetGlobal("__P8E_FUNCTION_greet_me")
			if err != nil {
				return err
			}
			value, _ := p8eTable.Get()
			memory, err := instance.Exports.GetMemory("memory")
			if err != nil {
				return err
			}
			data := memory.Data()
			tbl := value.(int32)
			ptr := binary.LittleEndian.Uint32(data[tbl : tbl+4])
			p8eFunctionDetailsLenG, err := instance.Exports.GetGlobal("__P8E_FUNCTION_LENGTH_greet_me")
			value, _ = p8eFunctionDetailsLenG.Get()
			p8eFunctionDetailsLen := value.(int32)
			p8eFunctionDetailsLenValue := binary.LittleEndian.Uint32(data[p8eFunctionDetailsLen : p8eFunctionDetailsLen+4])
			p8eFunctionDetailsValue := string(data[ptr : ptr+p8eFunctionDetailsLenValue])
			log.Printf("p8e function table len: %d\n", p8eFunctionDetailsLenValue)
			log.Printf("p8e function table: %s\n", p8eFunctionDetailsValue)
			var functionDetails P8eFunction
			err = json.Unmarshal([]byte(p8eFunctionDetailsValue), &functionDetails)
			if err != nil {
				return err
			}
			indented, err := json.MarshalIndent(functionDetails, "", " ")
			log.Printf("function details: %s", indented)

			err = greetMe(instance, "your majesty")
			if err != nil {
				log.Printf("Error greeting via binary proto: %v", err)
			}

			return nil
		},
	}
}

type Allocation struct {
	data interface{}
	len  int32
}

func allocateNameRequest(name string, allocator func(...interface{}) (interface{}, error), memory *wasmer.Memory) (*Allocation, error) {
	nameRequest := hello.Hello{
		Name: name,
	}
	nameRequestBytes, err := proto.Marshal(&nameRequest)
	if err != nil {
		return nil, err
	}
	dataLen := len(nameRequestBytes)
	ptr, err := allocator(dataLen)
	if err != nil {
		return nil, err
	}
	data := memory.Data()
	copy(data[ptr.(int32):], nameRequestBytes) // put name proto in wasm memory

	return &Allocation{
		data: ptr,
		len:  int32(dataLen),
	}, nil
}

func greetMe(instance *wasmer.Instance, name string) error {
	greetProto, err := instance.Exports.GetFunction("__p8e_entrypoint_greet_me")
	if err != nil {
		return err
	}

	memory, err := instance.Exports.GetMemory("memory")
	if err != nil {
		return err
	}

	allocator, err := instance.Exports.GetFunction("p8e_allocate")
	if err != nil {
		return err
	}

	// allocate
	proposed, err := allocateNameRequest("proposed name", allocator, memory)
	if err != nil {
		return err
	}
	existing, err := allocateNameRequest("existing name", allocator, memory)
	if err != nil {
		return err
	}
	existingOptional, err := allocateNameRequest("existing optional", allocator, memory)
	if err != nil {
		return err
	}

	// execute
	result, err := greetProto(proposed.data, proposed.len, existing.data, existing.len, existingOptional.data, existingOptional.len)
	if err != nil {
		return err
	}

	data := memory.Data() // refresh data ptr as might have grown

	fmt.Printf("result pointer: %d\n", result.(int32))
	resPtr := result.(int32)
	resDataLen := int32(binary.LittleEndian.Uint32(data[resPtr:]))
	responseMsg := hello.HelloResponse{}
	proto.Unmarshal(data[resPtr+4:resPtr+4+resDataLen], &responseMsg)
	fmt.Printf("greet me result: %s\n", responseMsg.Response)

	free, err := instance.Exports.GetFunction("p8e_free")
	if err != nil {
		return err
	}

	// free up wasm memory from allocation after call
	free(proposed.data, proposed.len)
	free(existing.data, existing.len)
	free(existingOptional.data, existingOptional.len)
	free(resPtr, resDataLen+4)

	// re-fetch to inspect un-allocated data
	data = memory.Data()
	fmt.Printf("Unallocated proposed data section: %v\n", data[proposed.data.(int32):proposed.data.(int32)+proposed.len])
	fmt.Printf("Unallocated existing data section: %v\n", data[existing.data.(int32):existing.data.(int32)+existing.len])
	fmt.Printf("Unallocated existingOptional data section: %v\n", data[existingOptional.data.(int32):existingOptional.data.(int32)+existingOptional.len])
	fmt.Printf("Unallocated result data section: %v\n", data[resPtr:resPtr+4+resDataLen])

	return nil
}
