export type EncryptionAlgorithm = 'aes-128-cbc' | 'aes-192-cbc' | 'aes-256-cbc';
// TODO: Support the CCM and GCM algorithms
// | 'aes-128-ccm'
// | 'aes-192-ccm'
// | 'aes-256-ccm'
// | 'aes-128-gcm'
// | 'aes-192-gcm'
// | 'aes-256-gcm';

export interface EncryptionOptions {
  /**
   * key - a 16-bit, 24-bit, or 32-bit raw string used by the algorithms. The 16-bit string is used on algorithms that include 128. The 24-bit string is used on algorithms that include 192. The 32-bit string is used on algorithms that include 256
   */
  key: string;
  /**
   * iv - a 16-bit raw string initialization vector
   * Initialization vectors should be unpredictable and unique; ideally, they will be cryptographically random
   * @link https://en.wikipedia.org/wiki/Initialization_vector
   */
  iv: string;
  /**
   * algorithm - The cypher algorithm to be used to  encrypt the payload
   */
  algorithm: EncryptionAlgorithm;
}

export interface DecryptedResult {
  [key: string]: unknown;
}

export interface EncryptedResult {
  data: string;
}

export interface EncryptedData {
  data?: string;
}
