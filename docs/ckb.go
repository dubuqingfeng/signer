package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/nervosnetwork/ckb-sdk-go/address"
	"github.com/nervosnetwork/ckb-sdk-go/crypto/secp256k1"
	"github.com/nervosnetwork/ckb-sdk-go/rpc"
	"github.com/nervosnetwork/ckb-sdk-go/transaction"
	"github.com/nervosnetwork/ckb-sdk-go/types"
	"github.com/nervosnetwork/ckb-sdk-go/utils"
	"log"
)

func ckb() {
	client, err := rpc.Dial("https://testnet.ckb.dev/rpc")
	if err != nil {
		log.Fatalf("create rpc client error: %v", err)
	}

	key, err := secp256k1.HexToKey(PRIVATE_KEY)
	if err != nil {
		log.Fatalf("import private key error: %v", err)
	}

	systemScripts, err := utils.NewSystemScripts(client)
	if err != nil {
		log.Fatalf("load system script error: %v", err)
	}

	//toAddress, _ := hex.DecodeString("bf3e92da4911fa5f620e7b1fd27c2d0ddd0de744")
	changeScript, _ := key.Script(systemScripts)

	toAddress, _ := address.Parse("ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqg4w6hxs0zvlh6kfrwfjfleq8qpaw2r7pcx24f6u")
	tx := transaction.NewSecp256k1SingleSigTx(systemScripts)
	tx.Outputs = append(tx.Outputs, &types.CellOutput{
		Capacity: 10000000000,
		Lock:     toAddress.Script,
	})
	tx.Outputs = append(tx.Outputs, &types.CellOutput{
		Capacity: 989500000000,
		Lock: &types.Script{
			CodeHash: types.HexToHash("0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8"),
			HashType: types.HashTypeType,
			Args:     changeScript.Args,
		},
	})
	tx.OutputsData = [][]byte{{}, {}}

	group, witnessArgs, err := transaction.AddInputsForTransaction(tx, []*types.CellInput{
		{
			Since: 0,
			PreviousOutput: &types.OutPoint{
				TxHash: types.HexToHash("0xcaf2cfb17eb961f54e22f8ced8656aa152f64f53e3db35b99705ca6b3822b5be"),
				Index:  0,
			},
		},
	}, uint(len(transaction.Secp256k1SignaturePlaceholder)))

	if err != nil {
		log.Fatalf("add inputs to transaction error: %v", err)
	}

	err = transaction.SingleSignTransaction(tx, group, witnessArgs, key)
	if err != nil {
		log.Fatalf("sign transaction error: %v", err)
	}

	fromTransaction(tx)
	re, err := client.DryRunTransaction(context.Background(), tx)
	if err != nil {
		log.Fatalf("send transaction error: %v", err)
	}
	fmt.Println(re.Cycles)

	//fmt.Println(hash.String())
}

func fromCellDeps(deps []*types.CellDep) []cellDep {
	result := make([]cellDep, len(deps))
	for i := 0; i < len(deps); i++ {
		dep := deps[i]
		result[i] = cellDep{
			OutPoint: outPoint{
				TxHash: dep.OutPoint.TxHash,
				Index:  hexutil.Uint(dep.OutPoint.Index),
			},
			DepType: dep.DepType,
		}
	}
	return result
}

func fromInputs(inputs []*types.CellInput) []cellInput {
	result := make([]cellInput, len(inputs))
	for i := 0; i < len(inputs); i++ {
		input := inputs[i]
		result[i] = cellInput{
			Since: hexutil.Uint64(input.Since),
			PreviousOutput: outPoint{
				TxHash: input.PreviousOutput.TxHash,
				Index:  hexutil.Uint(input.PreviousOutput.Index),
			},
		}
	}
	return result
}

func fromOutputs(outputs []*types.CellOutput) []cellOutput {
	result := make([]cellOutput, len(outputs))
	for i := 0; i < len(outputs); i++ {
		output := outputs[i]
		result[i] = cellOutput{
			Capacity: hexutil.Uint64(output.Capacity),
			Lock: &script{
				CodeHash: output.Lock.CodeHash,
				HashType: output.Lock.HashType,
				Args:     output.Lock.Args,
			},
		}
		if output.Type != nil {
			result[i].Type = &script{
				CodeHash: output.Type.CodeHash,
				HashType: output.Type.HashType,
				Args:     output.Type.Args,
			}
		}
	}
	return result
}

func fromBytesArray(bytes [][]byte) []hexutil.Bytes {
	result := make([]hexutil.Bytes, len(bytes))
	for i, data := range bytes {
		result[i] = data
	}
	return result
}

type inTransaction struct {
	Version     hexutil.Uint    `json:"version"`
	CellDeps    []cellDep       `json:"cell_deps"`
	HeaderDeps  []types.Hash    `json:"header_deps"`
	Inputs      []cellInput     `json:"inputs"`
	Outputs     []cellOutput    `json:"outputs"`
	OutputsData []hexutil.Bytes `json:"outputs_data"`
	Witnesses   []hexutil.Bytes `json:"witnesses"`
}

type outPoint struct {
	TxHash types.Hash   `json:"tx_hash"`
	Index  hexutil.Uint `json:"index"`
}

type cellDep struct {
	OutPoint outPoint      `json:"out_point"`
	DepType  types.DepType `json:"dep_type"`
}

type cellInput struct {
	Since          hexutil.Uint64 `json:"since"`
	PreviousOutput outPoint       `json:"previous_output"`
}

type script struct {
	CodeHash types.Hash           `json:"code_hash"`
	HashType types.ScriptHashType `json:"hash_type"`
	Args     hexutil.Bytes        `json:"args"`
}

type cellOutput struct {
	Capacity hexutil.Uint64 `json:"capacity"`
	Lock     *script        `json:"lock"`
	Type     *script        `json:"type"`
}

func fromTransaction(tx *types.Transaction) inTransaction {
	result := inTransaction{
		Version:     hexutil.Uint(tx.Version),
		HeaderDeps:  tx.HeaderDeps,
		CellDeps:    fromCellDeps(tx.CellDeps),
		Inputs:      fromInputs(tx.Inputs),
		Outputs:     fromOutputs(tx.Outputs),
		OutputsData: fromBytesArray(tx.OutputsData),
		Witnesses:   fromBytesArray(tx.Witnesses),
	}
	r, _ := json.Marshal(result)
	fmt.Println(string(r))
	return result
}
