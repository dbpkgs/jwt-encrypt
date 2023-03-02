# JWT Encrypt

A JWT encryption and decryption library for node server and web applications

This library provides a more granular encryption as it strives solve the vulnarabilities in the crypto encryption and descryption by using the latest `createCipheriv` and `createDecipheriv` as per the deprecation notice on `createCipher` and `createDecipher` which is currently semantically insecure for all supported ciphers and fattally flawed for ciphers in counter mode such as `(CTR, GCM or CCM)`.

## Installation

```bash
npm install jwt-encrypt
```

or

```bash
yarn add jwt-encrypt
```

## Usage

### Sign Token
