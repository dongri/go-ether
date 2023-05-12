package goether

import (
	"testing"
)

const (
	Address    = "0x0c9B5d5C6f4f095DA9Db0685689b6a22b0bF17C6"
	PrivateKey = "cc9c0c2a98e539a19cfb44f674b4a1fb1f07e0072184cbdcd0524136542ea060"
)

func TestSignKeccak256Message(t *testing.T) {
	expected := "0xa4e0f0d47bff7cb35f4eeaf9acd22f8e9c8a72aafd69fa9af304dbe9d76c95bf752c1f259df260296eaabd9537fae31b63cbf34db6692036edd9a7f94ed1c2cb1b"
	message := "hello world"
	address := "0x1cE28c56C1Eb78C2d8c0059f37f6BF2B21484616"
	value := "100000000000000000000000"
	types := []string{"string", "address", "uint256"}
	args := []string{message, address, value}
	signature, err := SignKeccak256Message(types, args, PrivateKey)
	if err != nil {
		t.Errorf("SignMessage() error = %v", err)
	}
	if signature == "" {
		t.Errorf("SignMessage() signature = %v", signature)
	}
	if signature != expected {
		t.Errorf("SignMessage() signature = %v, expected = %v", signature, expected)
	}
}

func TestPersonalSign(t *testing.T) {
	expected := "0x606de978a032b43674b9a3d88b78ac3ce84a26acd201157afe6101b712d0a4517839cc24ae98687250f6dda0cb15661ecea8130ef8af968e5b0250ad65efa3fc1b"
	hello := "hello"
	world := "world"
	message := hello + world
	signature, err := PersonalSign(message, PrivateKey)
	if err != nil {
		t.Errorf("PersonalSign() error = %v", err)
	}
	if signature == "" {
		t.Errorf("PersonalSign() signature = %v", signature)
	}
	if signature != expected {
		t.Errorf("PersonalSign() signature = %v, expected = %v", signature, expected)
	}
}

func TestVerifyPersonalSign(t *testing.T) {
	hello := "hello"
	world := "world"
	message := hello + world
	signature, err := PersonalSign(message, PrivateKey)
	if err != nil {
		t.Errorf("PersonalSign() error = %v", err)
	}
	verified, _, err := VerifyPersonalSign(signature, message, Address)
	if err != nil {
		t.Errorf("VerifySignature() error = %v", err)
	}
	if !verified {
		t.Errorf("VerifySignature() verified = %v", verified)
	}
}

func TestPrivateKeyToAddress(t *testing.T) {
	expected := Address
	privateKeyString := PrivateKey
	address, err := PrivateKeyToAddress(privateKeyString)
	if err != nil {
		t.Errorf("PrivateKeyToAddress() error = %v", err)
	}
	if address != expected {
		t.Errorf("PrivateKeyToAddress() address = %v, expected = %v", address, expected)
	}
}
