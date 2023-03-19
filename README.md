# Go Ether

## Test Wallet
https://github.com/dongri/web3/tree/master/ethereum-wallet-generator

```
mnemonic : daughter mimic all potato spare scheme term claim acid segment either ritual

private key 0: 0xcc9c0c2a98e539a19cfb44f674b4a1fb1f07e0072184cbdcd0524136542ea060
address     0: 0x0c9B5d5C6f4f095DA9Db0685689b6a22b0bF17C6
```

## Usage
```go
import (
  goether "github.com/dongri/go-ether"
)
goether.PersonalSign("message", "privateKey")
```

## SignKeccak256Message
```go
privateKey := "cc9c0c2a98e539a19cfb44f674b4a1fb1f07e0072184cbdcd0524136542ea060"
message := "hello world"
address := "0x1cE28c56C1Eb78C2d8c0059f37f6BF2B21484616"
value := "1000000000000000000"
types := []string{"string", "address", "uint256"}
args := []string{message, address, value}
signature, err := goether.SignKeccak256Message(types, args, privateKey)
```

Like Web3.js
```javascript
const sha3message = web3.utils.soliditySha3("hello world", "0x1cE28c56C1Eb78C2d8c0059f37f6BF2B21484616", "1000000000000000000")
const signature = await web3.eth.accounts.sign(sha3message, privateKey)
```

Verify Solidity
```solidity
function _verify(bytes32 __data, bytes memory __signature, address __account) internal pure returns (bool) {
  return __data
    .toEthSignedMessageHash()
    .recover(__signature) == __account;
}
```

## PersonalSign
Like Web3.js
```javascript
const message = "helloworld"
const signature = await web3.eth.personal.sign(message, account)
```

## VerifyPersonalSign
Like Web3.js
```javascript
const message = "helloworld"
const recovered = await web3.eth.personal.ecRecover(message, signature)
```
