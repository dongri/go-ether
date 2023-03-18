package goether

import (
	"errors"
	"math/big"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
)

func parseTypedData(types []string, args []string) ([]byte, error) {
	typeLen := len(types)
	argLen := len(args)
	if typeLen != argLen {
		return nil, errors.New("type and arg length not match")
	}
	data := []byte{}
	for i, typ := range types {
		switch typ {
		case "string":
			data = append(data, []byte(args[i])...)
		case "address":
			data = append(data, common.HexToAddress(args[i]).Bytes()...)
		case "uint256":
			i, err := strconv.ParseInt(args[i], 10, 64)
			if err != nil {
				return nil, err
			}
			bi := big.NewInt(i)
			data = append(data, common.LeftPadBytes(bi.Bytes(), 32)...)
		}
	}
	return data, nil
}
