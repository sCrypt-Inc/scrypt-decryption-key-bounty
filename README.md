# sCrypt Decryption Key Bounty

A solution that enables two parties to trade the decryption key for some cyphertext via Bitcoin.
This example implements trading a Poseidon key.


## Testing

Make sure you got Go, Circom and SnarkJS installed and properly configured. Use Circom version 2.0.2.

Download the sCrypt compiler binary:
```sh
npx scryptlib download 
```

Get an already prepared power of tau file by running:
```sh
wget https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_22.ptau -O pot22_final.ptau
```

Run tests:
```sh
npm run test
```
