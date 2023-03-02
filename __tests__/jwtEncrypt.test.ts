import jwte from '../index';

import type { EncryptionOptions } from '../types';

describe('"sign" - signing a token asynchronously', () => {
  describe('"sign" jwt token success', () => {
    it('should to return a signed jwt token when using "aes-256-cbc" encryption algorithm', () => {
      const payload = { test: 'test' };
      const jwtSecret = 'secret';
      const encryptionOptions: EncryptionOptions = {
        algorithm: 'aes-256-cbc',
        iv: 'abcd1234abcd1234', // 16-bit string
        key: 'abcd1234abcd1234efgh5678efgh5678', // 32-bit string
      };

      const signedToken = jwte.sign(payload, jwtSecret, encryptionOptions, {
        expiresIn: '1min',
      });

      expect(signedToken).toBeDefined();
      expect(typeof signedToken).toBe('string');
    });

    it('should to return a signed jwt token when using "aes-192-cbc" encryption algorithm', () => {
      const payload = { test: 'test' };
      const jwtSecret = 'secret';
      const encryptionOptions: EncryptionOptions = {
        algorithm: 'aes-192-cbc',
        iv: 'abcd1234abcd1234', // 16-bit string
        key: 'abcd1234abcd1234efgh5678', // 24-bit string
      };

      const signedToken = jwte.sign(payload, jwtSecret, encryptionOptions, {
        expiresIn: '1min',
      });

      expect(signedToken).toBeDefined();
      expect(typeof signedToken).toBe('string');
    });

    it('should to return a signed jwt token when using "aes-128-cbc" encryption algorithm', () => {
      const payload = { test: 'test' };
      const jwtSecret = 'secret';
      const encryptionOptions: EncryptionOptions = {
        algorithm: 'aes-128-cbc',
        iv: 'abcd1234abcd1234', // 16-bit string
        key: 'abcd1234abcd1234', // 16-bit string
      };

      const signedToken = jwte.sign(payload, jwtSecret, encryptionOptions, {
        expiresIn: '1min',
      });

      expect(signedToken).toBeDefined();
      expect(typeof signedToken).toBe('string');
    });
  });

  describe('"sign" jwt token error on wrong key', () => {
    it('should throw an error signing a jwt token using "aes-256-cbc" encryption algorithm wihout providing a key', () => {
      const payload = { test: 'test' };
      const jwtSecret = 'secret';
      const encryptionOptions: EncryptionOptions = {
        algorithm: 'aes-256-cbc',
        iv: 'abcd1234abcd1234', // 16-bit string
        key: '',
      };

      const errorMessage = 'Missing encyption key';

      expect(() => {
        jwte.sign(payload, jwtSecret, encryptionOptions, {
          expiresIn: '1min',
        });
      }).toThrowError(errorMessage);
    });

    it('should throw an error signing a jwt token using "aes-256-cbc" encryption algorithm with a key not equal to 32-bit string', () => {
      const payload = { test: 'test' };
      const jwtSecret = 'secret';
      const encryptionOptions: EncryptionOptions = {
        algorithm: 'aes-256-cbc',
        iv: 'abcd1234abcd1234', // 16-bit string
        key: 'abcd1234abcd1234efgh5678efgh567', // 31-bit string
      };

      const errorMessage = 'Encryption key must be a 32-bit string. Received 31-bit string';

      expect(() => {
        jwte.sign(payload, jwtSecret, encryptionOptions, {
          expiresIn: '1min',
        });
      }).toThrowError(errorMessage);
    });

    it('should throw an error signing a jwt token using "aes-192-cbc" encryption algorithm with a key not equal to 24-bit string', () => {
      const payload = { test: 'test' };
      const jwtSecret = 'secret';
      const encryptionOptions: EncryptionOptions = {
        algorithm: 'aes-192-cbc',
        iv: 'abcd1234abcd1234', // 16-bit string
        key: 'abcd1234abcd1234efgh5678e', // 25-bit string
      };

      const errorMessage = 'Encryption key must be a 24-bit string. Received 25-bit string';

      expect(() => {
        jwte.sign(payload, jwtSecret, encryptionOptions, {
          expiresIn: '1min',
        });
      }).toThrowError(errorMessage);
    });

    it('should throw an error signing a jwt token using "aes-128-cbc" encryption algorithm with a key not equal to 16-bit string', () => {
      const payload = { test: 'test' };
      const jwtSecret = 'secret';
      const encryptionOptions: EncryptionOptions = {
        algorithm: 'aes-128-cbc',
        iv: 'abcd1234abcd1234', // 16-bit string
        key: 'abcd1234abcd123', // 15-bit string
      };

      const errorMessage = 'Encryption key must be a 16-bit string. Received 15-bit string';

      expect(() => {
        jwte.sign(payload, jwtSecret, encryptionOptions, {
          expiresIn: '1min',
        });
      }).toThrowError(errorMessage);
    });
  });

  describe('"sign" jwt token error on wrong iv (initialization vector)', () => {
    it('should throw an error signing a jwt token using "aes-256-cbc" encryption algorithm without providing an iv', () => {
      const payload = { test: 'test' };
      const jwtSecret = 'secret';
      const encryptionOptions: EncryptionOptions = {
        algorithm: 'aes-256-cbc',
        iv: '',
        key: 'abcd1234abcd1234efgh5678efgh5678', // 32-bit string
      };

      const errorMessage = 'Missing encryption iv(initialization vector)';

      expect(() => {
        jwte.sign(payload, jwtSecret, encryptionOptions, {
          expiresIn: '1min',
        });
      }).toThrowError(errorMessage);
    });

    it('should throw an error signing a jwt token using "aes-256-cbc" encryption algorithm with an iv not equal to 16-bit string', () => {
      const payload = { test: 'test' };
      const jwtSecret = 'secret';
      const encryptionOptions: EncryptionOptions = {
        algorithm: 'aes-256-cbc',
        iv: 'abcd1234abcd1234a', // 15-bit string
        key: 'abcd1234abcd1234efgh5678efgh5678', // 32-bit string
      };

      const errorMessage = 'Encryption iv(initialization vector) must be a 16-bit string: Received 17-bit string';

      expect(() => {
        jwte.sign(payload, jwtSecret, encryptionOptions, {
          expiresIn: '1min',
        });
      }).toThrowError(errorMessage);
    });

    it('should throw an error signing a jwt token using "aes-192-cbc" encryption algorithm with an iv not equal to 16-bit string', () => {
      const payload = { test: 'test' };
      const jwtSecret = 'secret';
      const encryptionOptions: EncryptionOptions = {
        algorithm: 'aes-192-cbc',
        iv: 'abcd1234abcd123', // 15-bit string
        key: 'abcd1234abcd1234efgh5678', // 24-bit string
      };

      const errorMessage = 'Encryption iv(initialization vector) must be a 16-bit string: Received 15-bit string';

      expect(() => {
        jwte.sign(payload, jwtSecret, encryptionOptions, {
          expiresIn: '1min',
        });
      }).toThrowError(errorMessage);
    });

    it('should throw an error signing a jwt token using "aes-128-cbc" encryption algorithm with an iv not equal to 16-bit string', () => {
      const payload = { test: 'test' };
      const jwtSecret = 'secret';
      const encryptionOptions: EncryptionOptions = {
        algorithm: 'aes-128-cbc',
        iv: 'abcd1234abcd1234abcd', // 20-bit string
        key: 'abcd1234abcd1234', // 16-bit string
      };

      const errorMessage = 'Encryption iv(initialization vector) must be a 16-bit string: Received 20-bit string';

      expect(() => {
        jwte.sign(payload, jwtSecret, encryptionOptions, {
          expiresIn: '1min',
        });
      }).toThrowError(errorMessage);
    });
  });
});

describe('"decode" - decoding a signed jwt token without verifying if its valid', () => {
  describe('"decode" signed jwt token success', () => {
    it('should to return decoded value when using "aes-256-cbc" encryption algorithm', () => {
      const payload = { test: 'test' };
      const jwtSecret = 'secret';

      const encryptionOptions: EncryptionOptions = {
        algorithm: 'aes-256-cbc',
        iv: 'abcd1234abcd1234', // 16-bit string
        key: 'abcd1234abcd1234efgh5678efgh5678', // 32-bit string
      };

      const signedToken = jwte.sign(payload, jwtSecret, encryptionOptions, {
        expiresIn: '1min',
      });

      expect(signedToken).toBeDefined();
      expect(typeof signedToken).toBe('string');

      const decodedToken = jwte.decode(signedToken, encryptionOptions);

      expect(decodedToken).toHaveProperty('test');
      expect(decodedToken).toHaveProperty('iat');
      expect(decodedToken).toHaveProperty('exp');
      expect(typeof decodedToken).not.toBe('string');
      expect(typeof decodedToken !== 'string' && decodedToken?.test).toStrictEqual(payload.test);
    });

    it('should to return decoded value when using "aes-192-cbc" encryption algorithm', () => {
      const payload = { test: 'test' };
      const jwtSecret = 'secret';

      const encryptionOptions: EncryptionOptions = {
        algorithm: 'aes-192-cbc',
        iv: 'abcd1234abcd1234', // 16-bit string
        key: 'abcd1234abcd1234efgh5678', // 24-bit string
      };

      const signedToken = jwte.sign(payload, jwtSecret, encryptionOptions, {
        expiresIn: '1min',
      });

      expect(signedToken).toBeDefined();
      expect(typeof signedToken).toBe('string');

      const decodedToken = jwte.decode(signedToken, encryptionOptions);

      expect(decodedToken).toHaveProperty('test');
      expect(decodedToken).toHaveProperty('iat');
      expect(decodedToken).toHaveProperty('exp');
      expect(typeof decodedToken).not.toBe('string');
      expect(typeof decodedToken !== 'string' && decodedToken?.test).toStrictEqual(payload.test);
    });

    it('should to return decoded value when using "aes-128-cbc" encryption algorithm', () => {
      const payload = { test: 'test' };
      const jwtSecret = 'secret';

      const encryptionOptions: EncryptionOptions = {
        algorithm: 'aes-128-cbc',
        iv: 'abcd1234abcd1234', // 16-bit string
        key: 'abcd1234abcd1234', // 16-bit string
      };

      const signedToken = jwte.sign(payload, jwtSecret, encryptionOptions, {
        expiresIn: '1min',
      });

      expect(signedToken).toBeDefined();
      expect(typeof signedToken).toBe('string');

      const decodedToken = jwte.decode(signedToken, encryptionOptions);

      expect(decodedToken).toHaveProperty('test');
      expect(decodedToken).toHaveProperty('iat');
      expect(decodedToken).toHaveProperty('exp');
      expect(typeof decodedToken).not.toBe('string');
      expect(typeof decodedToken !== 'string' && decodedToken?.test).toStrictEqual(payload.test);
    });

    it('should to return complete decoded value when jwt option complete set as true ', () => {
      const payload = { test: 'test' };
      const jwtSecret = 'secret';

      const encryptionOptions: EncryptionOptions = {
        algorithm: 'aes-256-cbc',
        iv: 'abcd1234abcd1234', // 16-bit string
        key: 'abcd1234abcd1234efgh5678efgh5678', // 32-bit string
      };

      const signedToken = jwte.sign(payload, jwtSecret, encryptionOptions, {
        expiresIn: '1min',
      });

      expect(signedToken).toBeDefined();
      expect(typeof signedToken).toBe('string');

      const decodedToken = jwte.decode(signedToken, encryptionOptions, {
        complete: true,
      });

      expect(typeof decodedToken).not.toBe('string');

      if (typeof decodedToken !== 'string') {
        expect(decodedToken).toHaveProperty('payload');
        expect(decodedToken).toHaveProperty('header');
        expect(decodedToken).toHaveProperty('signature');
        expect(decodedToken?.payload).toHaveProperty('test');
        expect(decodedToken?.header).toHaveProperty('alg');
        expect(decodedToken?.header).toHaveProperty('typ');

        expect(decodedToken?.payload?.test).toStrictEqual(payload.test);
        expect(decodedToken?.header?.alg).toEqual('HS256');
        expect(decodedToken?.header?.typ).toEqual('JWT');
      }
    });

    it('should to return a string decoded value ', () => {
      const payload = 'test';
      const jwtSecret = 'secret';

      const encryptionOptions: EncryptionOptions = {
        algorithm: 'aes-256-cbc',
        iv: 'abcd1234abcd1234', // 16-bit string
        key: 'abcd1234abcd1234efgh5678efgh5678', // 32-bit string
      };

      const signedToken = jwte.sign(payload, jwtSecret, encryptionOptions, {
        expiresIn: '1min',
      });

      expect(signedToken).toBeDefined();
      expect(typeof signedToken).toBe('string');

      const decodedToken = jwte.decode(signedToken, encryptionOptions);

      expect(typeof decodedToken).toBe('string');
      expect(decodedToken).toBe(payload);
      expect(typeof decodedToken).not.toBe('object');
    });

    it('should to return a string decoded payload value when jwt option complete is set as true ', () => {
      const payload = 'test';
      const jwtSecret = 'secret';

      const encryptionOptions: EncryptionOptions = {
        algorithm: 'aes-256-cbc',
        iv: 'abcd1234abcd1234', // 16-bit string
        key: 'abcd1234abcd1234efgh5678efgh5678', // 32-bit string
      };

      const signedToken = jwte.sign(payload, jwtSecret, encryptionOptions, {
        expiresIn: '1min',
      });

      expect(signedToken).toBeDefined();
      expect(typeof signedToken).toBe('string');

      const decodedToken = jwte.decode(signedToken, encryptionOptions, {
        complete: true,
      });

      expect(typeof decodedToken).not.toBe('string');
      expect(typeof decodedToken).toBe('object');

      if (typeof decodedToken !== 'string') {
        expect(decodedToken).toHaveProperty('payload');
        expect(decodedToken).toHaveProperty('header');
        expect(decodedToken).toHaveProperty('signature');
        expect(typeof decodedToken?.payload).toBe('string');
        expect(decodedToken?.header).toHaveProperty('alg');
        expect(decodedToken?.header).toHaveProperty('typ');

        expect(decodedToken?.payload).toStrictEqual(payload);
        expect(decodedToken?.header?.alg).toEqual('HS256');
        expect(decodedToken?.header?.typ).toEqual('JWT');
      }
    });
  });
});

describe('"verify" - decoding a signed jwt token and verifying if its valid', () => {
  describe('"verify" signed jwt token success', () => {
    it('should to return a verified signed token value', () => {
      const payload = { test: 'test' };
      const jwtSecret = 'secret';

      const encryptionOptions: EncryptionOptions = {
        algorithm: 'aes-256-cbc',
        iv: 'abcd1234abcd1234', // 16-bit string
        key: 'abcd1234abcd1234efgh5678efgh5678', // 32-bit string
      };

      const signedToken = jwte.sign(payload, jwtSecret, encryptionOptions, {
        expiresIn: '1min',
      });

      expect(signedToken).toBeDefined();
      expect(typeof signedToken).toBe('string');

      jwte.verify(signedToken, jwtSecret, encryptionOptions, {}, (err, verifiedToken) => {
        expect(verifiedToken).toHaveProperty('test');
        expect(verifiedToken).toHaveProperty('iat');
        expect(verifiedToken).toHaveProperty('exp');
        expect(typeof verifiedToken).not.toBe('string');
        expect(
          ///@ts-expect-error (2339) FIXME: Property 'test' does not exist on type 'string | JwtPayload | Jwt'.
          verifiedToken?.test,
        ).toStrictEqual(payload.test);
      });
    });

    it('should to return a complete verified signed token value when jwt option complete is set as true', () => {
      const payload = { test: 'test' };
      const jwtSecret = 'secret';

      const encryptionOptions: EncryptionOptions = {
        algorithm: 'aes-256-cbc',
        iv: 'abcd1234abcd1234', // 16-bit string
        key: 'abcd1234abcd1234efgh5678efgh5678', // 32-bit string
      };

      const signedToken = jwte.sign(payload, jwtSecret, encryptionOptions, {
        expiresIn: '1min',
      });

      expect(signedToken).toBeDefined();
      expect(typeof signedToken).toBe('string');

      jwte.verify(signedToken, jwtSecret, encryptionOptions, { complete: true }, (err, verifiedToken) => {
        expect(err).toBeNull();
        expect(typeof verifiedToken).not.toBe('string');

        if (typeof verifiedToken !== 'string') {
          expect(verifiedToken).toHaveProperty('payload');
          expect(verifiedToken).toHaveProperty('header');
          expect(verifiedToken).toHaveProperty('signature');
          expect(verifiedToken?.payload).toHaveProperty('test');
          expect(verifiedToken?.header).toHaveProperty('alg');
          expect(verifiedToken?.header).toHaveProperty('typ');

          expect(verifiedToken?.payload?.test).toStrictEqual(payload.test);
          expect(verifiedToken?.header?.alg).toEqual('HS256');
          expect(verifiedToken?.header?.typ).toEqual('JWT');
        }
      });
    });

    it('should return a verified signed token value when the payload is set as a string', () => {
      const payload = 'test';
      const jwtSecret = 'secret';

      const encryptionOptions: EncryptionOptions = {
        algorithm: 'aes-256-cbc',
        iv: 'abcd1234abcd1234', // 16-bit string
        key: 'abcd1234abcd1234efgh5678efgh5678', // 32-bit string
      };

      const signedToken = jwte.sign(payload, jwtSecret, encryptionOptions, {
        expiresIn: '1min',
      });

      expect(signedToken).toBeDefined();
      expect(typeof signedToken).toBe('string');

      jwte.verify(signedToken, jwtSecret, encryptionOptions, {}, (err, verifiedToken) => {
        expect(err).toBeNull();

        expect(typeof verifiedToken).toBe('string');
        expect(verifiedToken).toBe(payload);
        expect(typeof verifiedToken).not.toBe('object');
      });
    });

    it('should throw an error while verifying a token with incorrect secret', () => {
      const payload = 'test';
      const jwtSecret = 'secret';

      const encryptionOptions: EncryptionOptions = {
        algorithm: 'aes-256-cbc',
        iv: 'abcd1234abcd1234', // 16-bit string
        key: 'abcd1234abcd1234efgh5678efgh5678', // 32-bit string
      };

      const signedToken = jwte.sign(payload, jwtSecret, encryptionOptions, {
        expiresIn: '1min',
      });

      expect(signedToken).toBeDefined();
      expect(typeof signedToken).toBe('string');

      jwte.verify(signedToken, 'wrong-secret', encryptionOptions, {}, (err, verifiedToken) => {
        expect(verifiedToken).toBeUndefined();

        expect(err).toBeDefined();
        expect(err).toBeInstanceOf(Error);
        expect(err?.name).toBe('JsonWebTokenError');
        expect(err?.message).toBe('invalid signature');
      });
    });

    it('should throw return void when verifying a token without providing a callback', () => {
      const payload = 'test';
      const jwtSecret = 'secret';

      const encryptionOptions: EncryptionOptions = {
        algorithm: 'aes-256-cbc',
        iv: 'abcd1234abcd1234', // 16-bit string
        key: 'abcd1234abcd1234efgh5678efgh5678', // 32-bit string
      };

      const signedToken = jwte.sign(payload, jwtSecret, encryptionOptions, {
        expiresIn: '1min',
      });

      expect(signedToken).toBeDefined();
      expect(typeof signedToken).toBe('string');

      const response = jwte.verify(signedToken, jwtSecret, encryptionOptions);

      expect(response).toBeUndefined();
    });
  });
});
