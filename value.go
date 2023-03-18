package goether

import (
	"math/big"

	"github.com/ethereum/go-ethereum/params"
)

func WeiToEther(wei *big.Int) *big.Float {
	f := new(big.Float)
	f.SetPrec(236) //  IEEE 754 octuple-precision binary floating-point format: binary256
	f.SetMode(big.ToNearestEven)
	fWei := new(big.Float)
	fWei.SetPrec(236) //  IEEE 754 octuple-precision binary floating-point format: binary256
	fWei.SetMode(big.ToNearestEven)
	return f.Quo(fWei.SetInt(wei), big.NewFloat(params.Ether))
}

func EtherToWei(eth *big.Float) *big.Int {
	wei := new(big.Float).Mul(eth, big.NewFloat(params.Ether))
	weiInt, _ := wei.Int(nil)
	return weiInt
}

func WeiToEtherStr(wei string) string {
	weiInt, ok := new(big.Int).SetString(wei, 10)
	if !ok {
		return ""
	}
	ether := WeiToEther(weiInt)
	return ether.String()
}

func EtherToWeiStr(ether string) string {
	etherFloat, ok := new(big.Float).SetString(ether)
	if !ok {
		return ""
	}
	wei := EtherToWei(etherFloat)
	return wei.String()
}
