import jwt from 'jsonwebtoken';

import { Cipher } from './utils';

import type {
  DecodeOptions,
  EncryptedData,
  EncryptionOptions,
  SignOptions,
  Secret,
  Jwt,
  JwtPayload,
  VerifyOptions,
  VerifyCallback,
  VerifyErrors,
} from './types';

export * from './types';

/**
 * Encrypt jsonwebtoken (JWT)
 */
export default class JwtEncrypt {
  /**
   *
   * Synchronously sign the given payload into an encrypted JSON Web Token string payload
   *
   * @param {string | object | Buffer} payload - The payload to sign, could be a literal, buffer or string
   * @param {Secret} jwtSecretOrPrivateKey - Either the secret for HMAC algorithms, or the PEM encoded private key for RSA and ECDSA.
   * @param {EncryptionOptions} encryptionOptions  - Options for the encyption
   * @property {string} encryptionOptions.key - a 16-bit, 24-bit, or 32-bit raw string used by the algorithms. The 16-bit string is used on algorithms that include 128. The 24-bit string is used on algorithms that include 192. The 32-bit string is used on algorithms that include 256
   * @property {string} encryptionOptions.iv  - a 16-bit raw string initialization vector (iv)
   * @link https://en.wikipedia.org/wiki/Initialization_vector
   * @property {EncryptionAlgorithm} encryptionOptions.algorithm - The cypher algorithm to be used to  encrypt the payload
   * @param {SignOptions | undefined} jwtOptions - Options for the signature
   *
   * @returns {string} - The JSON Web Token string
   *
   */
  static sign(
    payload: string | object | Buffer,
    jwtSecretOrPrivateKey: Secret,
    encryptionOptions: EncryptionOptions,
    jwtOptions?: SignOptions | undefined,
  ): string {
    return jwt.sign(Cipher.encrypt(payload, encryptionOptions), jwtSecretOrPrivateKey, jwtOptions);
  }

  /**
   * Returns the decoded payload from an token with encrypted data without verifying if the signature is valid.
   *
   * @param {string} token - JWT string to decode with encrypted information
   * @param {EncryptionOptions} encryptionOptions  - Options for the encyption
   * @property {string} encryptionOptions.key -  a 16-bit, 24-bit, or 32-bit raw string used by the algorithms. The 16-bit string is used on algorithms that include 128. The 24-bit string is used on algorithms that include 192. The 32-bit string is used on algorithms that include 256
   * @property {string} encryptionOptions.iv  - a 16-bit raw string initialization vector (iv)
   * @link https://en.wikipedia.org/wiki/Initialization_vector
   * @property {EncryptionAlgorithm} encryptionOptions.algorithm - The cypher algorithm to be used to  encrypt the payload
   * @param {DecodeOptions | undefined} jwtDecodeOptions - jwt options for decoding a jwt token.
   *
   * @returns {string | JwtPayload | null} - The decoded Token
   */
  static decode(
    token: string,
    encryptionOptions: EncryptionOptions,
    jwtDecodeOptions?: DecodeOptions,
  ): string | JwtPayload | null {
    const decodedPayload = jwt.decode(token, jwtDecodeOptions);

    if (!decodedPayload || typeof decodedPayload === 'string') return null;

    if (jwtDecodeOptions?.complete) {
      const { payload, ...restPayload } = decodedPayload;

      const cipherPayload = Cipher.decrypt(payload.data, encryptionOptions);

      return { payload: cipherPayload, ...restPayload };
    }

    const { data, ...restPayload } = decodedPayload;

    const cipherPayload = Cipher.decrypt(data, encryptionOptions);

    if (typeof cipherPayload === 'string') return cipherPayload;

    return { ...cipherPayload, ...restPayload };
  }

  /**
   *
   * Synchronously verify given token with encrypted data using a secret or a public key to get a decoded token
   *
   * @param {string} token - JWT string to verify
   * @param {Secret} jwtSecretOrPrivateKey - Either the secret for HMAC algorithms, or the PEM encoded public key for RSA and ECDSA.
   * @param {EncryptionOptions} encryptionOptions  - Options for the encyption
   * @property {string} encryptionOptions.key -  a 16-bit, 24-bit, or 32-bit raw string used by the algorithms. The 16-bit string is used on algorithms that include 128. The 24-bit string is used on algorithms that include 192. The 32-bit string is used on algorithms that include 256
   * @property {string} encryptionOptions.iv  - a 16-bit raw string initialization vector (iv)
   * @link https://en.wikipedia.org/wiki/Initialization_vector
   * @property {EncryptionAlgorithm} encryptionOptions.algorithm - The cypher algorithm to be used to  encrypt the payload
   * @param {VerifyOptions } jwtVerifyOptions - Options for the verification
   * @param {VerifyCallback<string | JwtPayload | Jwt>} callback - A function which receives an error and verifiedPayload, can be used to perfom an action once the payload has been verified
   *
   * @returns {void}
   *
   */
  static verify(
    token: string,
    jwtSecretOrPrivateKey: Secret,
    encryptionOptions: EncryptionOptions,
    jwtVerifyOptions?: VerifyOptions,
    callback?: VerifyCallback<string | JwtPayload | Jwt>,
  ): void {
    let done: VerifyCallback<string | JwtPayload | Jwt>;

    if (callback) {
      done = callback;
    } else {
      done = function (err: VerifyErrors | null, data: string | JwtPayload | Jwt | undefined) {
        if (err) throw err;

        return data;
      };
    }

    jwt.verify(
      token,
      jwtSecretOrPrivateKey,
      jwtVerifyOptions,
      (err: VerifyErrors | null, verifiedPayload?: string | JwtPayload | (Jwt & EncryptedData)) => {
        if (err) {
          return done(err, undefined);
        }

        if (!verifiedPayload || typeof verifiedPayload === 'string') {
          return done(null, undefined);
        }

        if (jwtVerifyOptions?.complete) {
          const { payload, ...restPayload } = verifiedPayload;

          const cipherPayload = Cipher.decrypt(payload.data, encryptionOptions);

          return done(null, { payload: cipherPayload, ...restPayload });
        }

        const { data, ...restPayload } = verifiedPayload;

        const cipherPayload = Cipher.decrypt(data, encryptionOptions);

        if (typeof cipherPayload === 'string') return done(null, cipherPayload);

        return done(null, { ...cipherPayload, ...restPayload });
      },
    );
  }
}
