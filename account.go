package goether

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

const (
	MessagePrefix = "\x19Ethereum Signed Message:\n"
)

func SignKeccak256Message(types []string, args []string, privateKey string) (string, error) {
	byteData, err := parseTypedData(types, args)
	if err != nil {
		return "", err
	}
	keccak256Hash := crypto.Keccak256Hash(byteData)
	bytes := keccak256Hash.Bytes()
	prefixedMessage := fmt.Sprintf("%s%d%s", MessagePrefix, len(bytes), bytes)
	digestHash := crypto.Keccak256([]byte(prefixedMessage))
	prv, err := strToPrivateKey(privateKey)
	if err != nil {
		return "", err
	}
	signature, err := crypto.Sign(digestHash, prv)
	if err != nil {
		return "", err
	}
	signature[64] += 27
	return hexutil.Encode(signature), nil
}

func PersonalSign(message string, privateKey string) (string, error) {
	prefixedMessage := fmt.Sprintf("%s%d%s", MessagePrefix, len(message), message)
	hashedMessage := crypto.Keccak256Hash([]byte(prefixedMessage))

	prv, err := strToPrivateKey(privateKey)
	if err != nil {
		return "", err
	}
	signatureBytes, err := crypto.Sign(hashedMessage.Bytes(), prv)
	if err != nil {
		return "", err
	}
	signatureBytes[64] += 27
	signature := hexutil.Encode(signatureBytes)
	return signature, err
}

func VerifyPersonalSign(signature string, message string, address string) (bool, string, error) {
	prefixedMessage := fmt.Sprintf("%s%d%s", MessagePrefix, len(message), message)
	keccak256Hash := crypto.Keccak256Hash([]byte(prefixedMessage))
	decodedMessage := hexutil.MustDecode(signature)
	if decodedMessage[64] == 27 || decodedMessage[64] == 28 {
		decodedMessage[64] -= 27
	}
	sigPublicKeyECDSA, err := crypto.SigToPub(keccak256Hash.Bytes(), decodedMessage)
	if err != nil {
		return false, "", err
	}
	if sigPublicKeyECDSA == nil {
		return false, "", errors.New("could not get a public get from the message signature")
	}
	publicKey := crypto.PubkeyToAddress(*sigPublicKeyECDSA).String()
	if publicKey == address {
		return true, publicKey, nil
	}
	return false, "", nil
}

func PrivateKeyToAddress(privateKey string) (string, error) {
	prv, err := strToPrivateKey(privateKey)
	if err != nil {
		return "", err
	}
	publicKey := prv.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return "", errors.New("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}
	address := crypto.PubkeyToAddress(*publicKeyECDSA).String()
	return address, nil
}

// === Private funcs ===

func strToPrivateKey(str string) (*ecdsa.PrivateKey, error) {
	prv, err := crypto.HexToECDSA(remove0xPrefix(str))
	if err != nil {
		return nil, err
	}
	return prv, nil
}

func remove0xPrefix(s string) string {
	if len(s) >= 2 && s[:2] == "0x" {
		return s[2:]
	}
	return s
}

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
		case "bool":
			bool, err := strconv.ParseBool(args[i])
			if err != nil {
				return nil, err
			}
			if bool {
				data = append(data, []byte{0x01}...)
			} else {
				data = append(data, []byte{0x00}...)
			}
		case "uint8":
			b := new(bytes.Buffer)
			bn := new(big.Int)
			bn.SetString(args[i], 10)
			if err := binary.Write(b, binary.BigEndian, uint8(bn.Uint64())); err != nil {
				return nil, err
			}
			data = append(data, b.Bytes()...)
		case "uint16":
			b := new(bytes.Buffer)
			bn := new(big.Int)
			bn.SetString(args[i], 10)
			if err := binary.Write(b, binary.BigEndian, uint16(bn.Uint64())); err != nil {
				return nil, err
			}
			data = append(data, b.Bytes()...)
		case "uint32":
			b := new(bytes.Buffer)
			bn := new(big.Int)
			bn.SetString(args[i], 10)
			if err := binary.Write(b, binary.BigEndian, uint32(bn.Uint64())); err != nil {
				return nil, err
			}
			data = append(data, b.Bytes()...)
		case "uint64":
			b := new(bytes.Buffer)
			bn := new(big.Int)
			bn.SetString(args[i], 10)
			if err := binary.Write(b, binary.BigEndian, bn.Uint64()); err != nil {
				return nil, err
			}
			data = append(data, b.Bytes()...)
		case "uint128":
			i, err := strconv.ParseInt(args[i], 10, 64)
			if err != nil {
				return nil, err
			}
			bi := big.NewInt(i)
			data = append(data, common.LeftPadBytes(bi.Bytes(), 16)...)
		case "uint256":
			i, err := strconv.ParseInt(args[i], 10, 64)
			if err != nil {
				return nil, err
			}
			bi := big.NewInt(i)
			data = append(data, common.LeftPadBytes(bi.Bytes(), 32)...)
		case "int8":
			b := make([]byte, 1)
			bn := new(big.Int)
			bn.SetString(args[i], 10)
			b[0] = byte(int8(bn.Uint64()))
			data = append(data, b...)
		case "int16":
			b := make([]byte, 2)
			bn := new(big.Int)
			bn.SetString(args[i], 10)
			binary.BigEndian.PutUint16(b, uint16(bn.Uint64()))
			data = append(data, b...)
		case "int32":
			b := make([]byte, 4)
			bn := new(big.Int)
			bn.SetString(args[i], 10)
			binary.BigEndian.PutUint32(b, uint32(bn.Uint64()))
			data = append(data, b...)
		case "int64":
			b := make([]byte, 8)
			bn := new(big.Int)
			bn.SetString(args[i], 10)
			binary.BigEndian.PutUint64(b, bn.Uint64())
			data = append(data, b...)
		case "int128":
			bn := new(big.Int)
			bn.SetString(args[i], 10)
			data = append(data, common.LeftPadBytes(bn.Bytes(), 16)...)
		case "int256":
			bn := new(big.Int)
			bn.SetString(args[i], 10)
			data = append(data, common.LeftPadBytes(bn.Bytes(), 32)...)
		default:
			return nil, errors.New("unsupported type")
		}
	}
	return data, nil
}
