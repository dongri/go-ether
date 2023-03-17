package goether

import (
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

const (
	MessagePrefix = "\x19Ethereum Signed Message:\n"
)

func SignKeccak256Message(message string, privateKeyString string) (string, error) {
	privateKey, err := crypto.HexToECDSA(privateKeyString)
	if err != nil {
		return "", err
	}
	keccak256Hash := crypto.Keccak256Hash([]byte(message))
	bytes := keccak256Hash.Bytes()
	prefixedMessage := fmt.Sprintf("%s%d%s", MessagePrefix, len(bytes), bytes)
	digestHash := crypto.Keccak256([]byte(prefixedMessage))
	signature, err := crypto.Sign(digestHash, privateKey)
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
