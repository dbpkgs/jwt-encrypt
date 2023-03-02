import { Cipher } from '../utils';

import type { EncryptionOptions } from '../utils';

describe('"Cipher"', () => {
  describe('"Cipher.encrypt"', () => {
    it('should encrypt a given payload', () => {
      const payload = 'Test';
      const options: EncryptionOptions = {
        algorithm: 'aes-256-cbc',
        iv: 'abcd1234abcd1234', // 16-bit string
        key: 'abcd1234abcd1234efgh5678efgh5678', // 32-bit string
      };
      const expectedEncryptedResponse = 'ef26b4ac0b833be8a925b005a2e5ad45';

      const encryptedPayload = Cipher.encrypt(payload, options);

      expect(encryptedPayload).toBeDefined();
      expect(encryptedPayload).toHaveProperty('data');
      expect(typeof encryptedPayload.data).toBe('string');
      expect(encryptedPayload.data).toBe(expectedEncryptedResponse);
    });

    it('should throw encryption error when encrypting a given payload with wrong algorithm', () => {
      const payload = 'Test';
      const options: EncryptionOptions = {
        // Deliberately force the algorithm to a different algorithm to catch encryption errors
        //@ts-expect-error (2820): FIXME: Type '"aes-256-ccm"' is not assignable to type 'EncryptionAlgorithm'. Did you mean '"aes-256-cbc"
        algorithm: 'aes-256-ccm',
        iv: 'abcd1234abcd1234', // 16-bit string
        key: 'abcd1234abcd1234efgh5678efgh5678', // 32-bit string
      };

      const errorMessage = 'Error encrypting string. Please try again';

      expect(() => {
        Cipher.encrypt(payload, options);
      }).toThrowError(errorMessage);
    });
  });

  describe('"Cipher.decrypt"', () => {
    it('should decrypt a given encrypted payload', () => {
      const payload = 'Test';
      const options: EncryptionOptions = {
        algorithm: 'aes-256-cbc',
        iv: 'abcd1234abcd1234', // 16-bit string
        key: 'abcd1234abcd1234efgh5678efgh5678', // 32-bit string
      };
      const expectedEncryptedResponse = 'ef26b4ac0b833be8a925b005a2e5ad45';

      const encryptedPayload = Cipher.encrypt(payload, options);

      expect(encryptedPayload).toBeDefined();
      expect(encryptedPayload).toHaveProperty('data');
      expect(typeof encryptedPayload.data).toBe('string');
      expect(encryptedPayload.data).toBe(expectedEncryptedResponse);

      const decryptedPayload = Cipher.decrypt(encryptedPayload.data, options);

      expect(decryptedPayload).toBe(payload);
    });

    it('should throw an error when decrypting a given encrypted payload with wrong decryption options', () => {
      const payload = 'Test';
      const encryptionOptions: EncryptionOptions = {
        algorithm: 'aes-256-cbc',
        iv: 'abcd1234abcd1234', // 16-bit string
        key: 'abcd1234abcd1234efgh5678efgh5678', // 32-bit string
      };

      const decryptionOptions: EncryptionOptions = {
        algorithm: 'aes-256-cbc',
        iv: 'bbcd1234abcd1235', // 16-bit string
        key: 'bbcd1234abcd1234efgh5678efgh5670', // 32-bit string
      };

      const expectedEncryptedResponse = 'ef26b4ac0b833be8a925b005a2e5ad45';
      const errorMessage =
        'Error decrypting string. Ensure the text parameter is an encrypted string or the key and iv (initialization vector) are the same that were provided while encrypting';

      const encryptedPayload = Cipher.encrypt(payload, encryptionOptions);

      expect(encryptedPayload).toBeDefined();
      expect(encryptedPayload).toHaveProperty('data');
      expect(typeof encryptedPayload.data).toBe('string');
      expect(encryptedPayload.data).toBe(expectedEncryptedResponse);

      expect(() => {
        Cipher.decrypt(encryptedPayload.data, decryptionOptions);
      }).toThrowError(errorMessage);
    });
  });
});
