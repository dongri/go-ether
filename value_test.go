package goether

import (
	"math/big"
	"testing"
)

func TestWeiToEther(t *testing.T) {
	wei := big.NewInt(10000000000000000)
	ether := WeiToEther(wei).SetPrec(128)
	expected, _ := new(big.Float).SetPrec(128).SetString("0.01")
	if expected.Cmp(ether) != 0 {
		t.Errorf("WeiToEther: expected %v, got %v", expected, ether)
	}
}

func TestEtherToWei(t *testing.T) {
	ether := big.NewFloat(0.01)
	wei := EtherToWei(ether)
	if wei.Cmp(big.NewInt(10000000000000000)) != 0 {
		t.Errorf("EtherToWei: expected 1000000000000000000, got %v", wei)
	}
}

func TestWeiToEtherStr(t *testing.T) {
	expected := "0.01"
	wei := "10000000000000000"
	ether := WeiToEtherStr(wei)
	if ether != expected {
		t.Errorf("WeiToEtherStr: expected 0.01, got %v", ether)
	}
}

func TestEtherToWeiStr(t *testing.T) {
	expected := "10000000000000000"
	ether := "0.01"
	wei := EtherToWeiStr(ether)
	if wei != expected {
		t.Errorf("EtherToWeiStr: expected 10000000000000000, got %v", wei)
	}
}
