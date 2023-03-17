# Go Ether

## Test Data
https://github.com/dongri/web3/tree/master/ethereum-wallet-generator

```
mnemonic : daughter mimic all potato spare scheme term claim acid segment either ritual

private key 0: 0xcc9c0c2a98e539a19cfb44f674b4a1fb1f07e0072184cbdcd0524136542ea060
address     0: 0x0c9B5d5C6f4f095DA9Db0685689b6a22b0bF17C6
```

## SignKeccak256Message
Like Web3.js
```
const sha3message = web3.utils.soliditySha3("hello", "world")
const signature = await web3.eth.accounts.sign(sha3message, privateKey)
```

Verify Solidity
```sol
function _verify(bytes32 __data, bytes memory __signature, address __account) internal pure returns (bool) {
  return __data
    .toEthSignedMessageHash()
    .recover(__signature) == __account;
}
```

## PersonalSign
Like Web3.js
```
const message = "helloworld"
const signature = await web3.eth.personal.sign(message, account)
```

## VerifyPersonalSign
Like Web3.js
```
const message = "helloworld"
const recovered = await web3.eth.personal.ecRecover(message, signature)
```
