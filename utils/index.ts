import { createCipheriv, createDecipheriv } from 'crypto';

import type { EncryptionOptions, EncryptedResult, DecryptedResult } from '../types';

export class Cipher {
  private static validateEncryptionOptions(options: EncryptionOptions) {
    if (!options.key) {
      throw new Error('Missing encyption key');
    }

    if (!options.iv) {
      throw new Error('Missing encryption iv(initialization vector)');
    }

    if (options.algorithm.includes('256') && options.key.length !== 32) {
      throw new Error(`Encryption key must be a 32-bit string. Received ${options.key.length}-bit string`);
    }

    if (options.algorithm.includes('192') && options.key.length !== 24) {
      throw new Error(`Encryption key must be a 24-bit string. Received ${options.key.length}-bit string`);
    }

    if (options.algorithm.includes('128') && options.key.length !== 16) {
      throw new Error(`Encryption key must be a 16-bit string. Received ${options.key.length}-bit string`);
    }

    if (options.iv.length !== 16) {
      throw new Error(
        `Encryption iv(initialization vector) must be a 16-bit string: Received ${options.iv.length}-bit string`,
      );
    }
  }

  /**
   * Encrypts a given payload
   *
   * @param payload - The payload to sign, could be a literal, buffer or string to be encrypted
   *  @param {EncryptionOptions} options  - Options for the encyption
   * @property {string} options.key -  a 16-bit, 24-bit, or 32-bit raw string used by the algorithms. The 16-bit string is used on algorithms that include 128. The 24-bit string is used on algorithms that include 192. The 32-bit string is used on algorithms that include 256
   * @property {string} options.iv  - a 16-bit raw string initialization vector (iv)
   * @link https://en.wikipedia.org/wiki/Initialization_vector
   * @property {EncryptionAlgorithm} options.algorithm - The cypher algorithm to be used to  encrypt the payload
   *
   * @return {EncryptedResult}  encrypted result
   *
   */
  static encrypt(payload: string | object | Buffer, options: EncryptionOptions): EncryptedResult {
    Cipher.validateEncryptionOptions(options);

    try {
      const key = Buffer.from(options.key, 'utf-8');

      const iv = Buffer.from(options.iv, 'utf-8');

      // Creating the cipher with the above defined parameters
      const cipher = createCipheriv(options.algorithm, key, iv);

      // Updating the encrypted text...
      const encryptedCipher = cipher.update(JSON.stringify(payload), 'utf-8');

      // Returning the iv vector along with the encrypted data
      const encryptedData = Buffer.concat([encryptedCipher, cipher.final()]).toString('hex');

      return { data: encryptedData };
    } catch (err) {
      throw new Error('Error encrypting string. Please try again');
    }
  }

  /**
   * Encrypts a given encrypted string text
   *
   * @param text - The encrypted text string to be decrypted
   *  @param {EncryptionOptions} options  - Options for the decryption
   * @property {string} options.key -  a 16-bit, 24-bit, or 32-bit raw string used by the algorithms. The 16-bit string is used on algorithms that include 128. The 24-bit string is used on algorithms that include 192. The 32-bit string is used on algorithms that include 256
   * @property {string} options.iv  - a 16-bit raw string initialization vector (iv)
   * @link https://en.wikipedia.org/wiki/Initialization_vector
   * @property {EncryptionAlgorithm} options.algorithm - The cypher algorithm to be used to  decrypt the payload
   *
   * @return {string | DecryptedResult}  encrypted result
   *
   */
  static decrypt(text: string, options: EncryptionOptions): string | DecryptedResult {
    Cipher.validateEncryptionOptions(options);

    try {
      const key = Buffer.from(options.key, 'utf-8');

      const iv = Buffer.from(options.iv, 'utf-8');

      const encryptedText = Buffer.from(text, 'hex');

      // Creating the decipher from algo, key and iv
      const decipher = createDecipheriv(options.algorithm, key, iv);

      // Updating decrypted text
      const decryptedCipher = decipher.update(encryptedText);

      // returning response data after decryption
      const decryptedData = Buffer.concat([decryptedCipher, decipher.final()]).toString();

      return JSON.parse(decryptedData);
    } catch (err) {
      throw new Error(
        'Error decrypting string. Ensure the text parameter is an encrypted string or the key and iv (initialization vector) are the same that were provided while encrypting',
      );
    }
  }
}
