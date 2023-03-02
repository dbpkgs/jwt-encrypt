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

## Encryption algorithms supported

The encryption algorithms determine the key. The following shows the list algorithms supported and their key and iv(initialization vector) lengths required

| **Algorithm** | **Key Length** | **IV Length** |
| ------------- | -------------- | ------------- |
| aes-256-cbc   | 32             | 16            |
| aes-192-cbc   | 24             | 16            |
| aes-128-cbc   | 16             | 16            |

### Encryption options

```ts
{
  key: string; // a 16-bit, 24-bit, or 32-bit raw string used by the algorithms
  iv: string; // a 16-bit raw string initialization vector
  algorithm: 'aes-128-cbc' | 'aes-192-cbc' | 'aes-256-cbc'; // The cypher algorithm to be used to  encrypt the payload
}
```

## Usage

### Sign Token

(Synchronous) Returns the JsonWebToken containing encrypted payload as string

```ts
import jwte from 'jwt-encrypt';

const token = jwte.sign(payload, jwtSecret, encryptionOptions, jwtOptions);
```

#### Example Usage

```ts
import jwte from 'jwt-encrypt';

const payload = { test: 'test' };
const jwtSecret = 'secret';
const encryptionOptions = {
  algorithm: 'aes-256-cbc',
  iv: 'abcd1234abcd1234', // 16-bit string
  key: 'abcd1234abcd1234efgh5678efgh5678', // 32-bit string
};

const token = jwte.sign(payload, jwtSecret, encryptionOptions, {
  expiresIn: '1min',
});
```

### Decode Token

(Synchronously) Decode a given token with encrypted data.

_NB: While decoding you must provide the `algorithm`, `key` and `iv` that were used while signing the token_

```ts
import jwte from 'jwt-encrypt';

const decoded = jwte.decode(token, encryptionOptions);
```

#### Example Usage

```ts
import jwte from 'jwt-encrypt';

const payload = { test: 'test' };

const encryptionOptions = {
  algorithm: 'aes-256-cbc',
  iv: 'abcd1234abcd1234', // 16-bit string
  key: 'abcd1234abcd1234efgh5678efgh5678', // 32-bit string
};

const decoded = jwte.decode(token, encryptionOptions);
```

### Verify Token

(Asynchronous) If a callback is supplied, function acts asynchronously. The callback is called with the decoded payload if the signature is valid and optional expiration, audience, or issuer are valid. If not, it will be called with the error.

_NB: While verifying you must provide the `algorithm`, `key` and `iv` that were used while signing the token_

```ts
import jwte from 'jwt-encrypt';

jwte.verify(signedToken, jwtSecret, encryptionOptions, jwtOptions, (err, verifiedToken) => {});
```

#### Example Usage

```ts
import jwte from 'jwt-encrypt';

const payload = { test: 'test' };
const jwtSecret = 'secret';

const encryptionOptions = {
  algorithm: 'aes-256-cbc',
  iv: 'abcd1234abcd1234', // 16-bit string
  key: 'abcd1234abcd1234efgh5678efgh5678', // 32-bit string
};

const jwtOptions = {};

jwte.verify(signedToken, jwtSecret, encryptionOptions, jwtOptions, (err, verifiedToken) => {
  if (err) {
    console.log('Error', err);
  }

  console.log('VerifiedToken', verifiedToken);
});
```

## License

MIT
