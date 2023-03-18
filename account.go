package goether

import (
	"crypto/ecdsa"
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
	prv, err := crypto.HexToECDSA(privateKey)
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
	prv, err := crypto.HexToECDSA(privateKey)
	if err != nil {
		return "", err
	}
	prefixedMessage := fmt.Sprintf("%s%d%s", MessagePrefix, len(message), message)
	hashedMessage := crypto.Keccak256Hash([]byte(prefixedMessage))
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
	prv, err := crypto.HexToECDSA(privateKey)
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
		default:
			return nil, errors.New("unsupported type")
		}
	}
	return data, nil
}
