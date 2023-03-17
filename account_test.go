package goether

import (
	"testing"
)

const (
	Address    = "0x0c9B5d5C6f4f095DA9Db0685689b6a22b0bF17C6"
	PrivateKey = "cc9c0c2a98e539a19cfb44f674b4a1fb1f07e0072184cbdcd0524136542ea060"
)

func TestSignKeccak256Message(t *testing.T) {
	expected := "0xbbc3ce195c7102047d4d9bd7c8d5addbe1aca03926dc977ae944477865cbcb60080b11de23eded9a648f5d821f98a4b68165e09cad1ccbf9b75f72cc132feb051c"
	hello := "hello"
	world := "world"
	message := hello + world
	signature, err := SignKeccak256Message(message, PrivateKey)
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
