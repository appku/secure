import crypto from 'crypto';
import fs from 'fs';

/**
 * Provides a straight-forward set of encryption/decryption functions for encrypting content.
 * A limited subset of algorithms are supported.
 */
class Cryptography {
    constructor(algorithm, hashAlgorithm, encoding, outputEncoding) {

        /**
         * The algorithm to use. 
         * Supports:
         * - aes-128-ctr
         * - aes-192-ctr
         * - aes-256-ctr
         * Defaults to "aes-256-ctr".
         * @type {String}
         */
        this.algorithm = algorithm || 'aes-256-ctr';

        /**
         * The hasing algorithm to use. 
         * Supports:
         * - ripemd160
         * - sha256
         * - sha384
         * - sha512
         * - whirlpool
         * Defaults to "sha256".
         * @type {String}
         */
        this.hashAlgorithm = hashAlgorithm || 'sha256';

        /**
         * The text encoding. Defaults to "utf8".
         * @type {String}
         */
        this.encoding = encoding || 'utf8';

        /**
         * The encrypted text output encoding. Can be 'base64' or 'hex'.
         * @type {String}
         */
        this.outputEncoding = outputEncoding || 'base64';

        this.pbkdf2 = {
            iterations: 100
        };

        this._validateProperties();
    }

    /**
     * Validates the class properties.
     * @private
     */
    _validateProperties() {
        if (!this.algorithm || !this.algorithm.match(/aes-(?:128|192|256)-ctr/)) {
            throw new Error(`Invalid or un-supported algorithm value: "${this.algorithm}".`);
        }
        if (!this.hashAlgorithm || !this.hashAlgorithm.match(/ripemd160|sha256|sha384|sha512|whirlpool/)) {
            throw new Error(`Invalid or un-supported hash algorithm value: "${this.hashAlgorithm}".`);
        }
        if (!this.encoding || !this.encoding.match(/utf8|ascii/)) {
            throw new Error(`Invalid or un-supported encoding value: "${this.encoding}".`);
        }
        if (!this.outputEncoding || !this.outputEncoding.match(/base64|hex/)) {
            throw new Error(`Invalid or un-supported outputEncoding value: "${this.outputEncoding}".`);
        }
    }

    /**
     * Returns the key size of the specified algorithm.
     * @param {String} algorithm - The cryptographic algorithm to get the key size for.
     * @returns {Number}
     * @private
     */
    _keyLength(algorithm) {
        switch (algorithm) {
            case 'aes-128-ctr': return 16;
            case 'aes-192-ctr': return 24;
            case 'aes-256-ctr': return 32;
        }
        return -1;
    }

    /**
     * Creates a pbkdf2 derived key from the given password and salt.
     * @param {String} password - The password to derive a key from.
     * @param {String} salt - A random salt value.
     * @returns {Promise.<Buffer>} 
     */
    async pbkdf2Key(password, salt) {
        let self = this;
        let key = {
            data: null,
            salt: Buffer.from(salt || '', self.encoding)
        };
        return new Promise((resolve, reject) => {
            crypto.pbkdf2(
                password,
                key.salt,
                self.pbkdf2.iterations,
                self._keyLength(self.algorithm),
                self.hashAlgorithm,
                (err, derivedKey) => {
                    if (err) {
                        reject(err);
                    } else {
                        key.data = derivedKey;
                        resolve(key);
                    }
                });
        });
    }

    /**
     * Encrypts a string of text using the given password and salt.
     * @param {String} text - The string of text to encrypt.
     * @param {String|{data:Buffer, salt:Buffer}} password - The password to derive a key from.
     * @param {String} [salt] - A random salt value.
     * @returns {Promise.<String>}
     */
    async encryptText(text, password, salt) {
        if (text === null) {
            return null;
        }
        let encrypted = await this.encryptBuffer(Buffer.from(text, this.encoding), password, salt);
        return encrypted.toString(this.outputEncoding);
    }

    /**
     * Decrypts a string of text using the given password and salt.
     * @param {String} text - The string of text to decrypt.
     * @param {String|{data:Buffer, salt:Buffer}} password - The password to derive a key from.
     * @param {String} [salt] - A random salt value.
     * @returns {Promise.<String>}
     */
    async decryptText(text, password, salt) {
        if (text === null) {
            return null;
        }
        let decrypted = await this.decryptBuffer(Buffer.from(text, this.outputEncoding), password, salt);
        return decrypted.toString(this.encoding);
    }

    /**
     * Encrypts a buffer using the given password and salt.
     * @param {Buffer} buffer - The buffer to encrypt.
     * @param {String|{data:Buffer, salt:Buffer}} password - The password to derive a key from.
     * @param {String} [salt] - A random salt value.
     * @returns {Promise.<Buffer>}
     */
    async encryptBuffer(buffer, password, salt) {
        //validations & escapes
        if (buffer === null) {
            return null;
        } else if (Buffer.isBuffer(buffer) === false) {
            throw new Error('The "buffer" parameter argument must be a Buffer instance.');
        }
        if (!password) {
            throw new Error('A "password" parameter argument is required.');
        } else if (!password.data && !password.salt && typeof password !== 'string') {
            throw new Error('A "password" parameter argument must be a string or pbkdf2 derived key.');
        }
        if (salt && typeof salt !== 'string') {
            throw new Error('The "salt" parameter argument must be a string if specified.');
        }
        this._validateProperties();
        //encrypt the data
        let key = null;
        if (password.data && password.salt) {
            key = password;
            if (typeof salt !== 'undefined') {
                throw new Error('The "salt" parameter cannot be used when providing a pbkdf2 derived key.');
            }
        } else {
            key = await this.pbkdf2Key(password, salt);
        }
        var iv = crypto.randomBytes(16);
        var cipher = crypto.createCipheriv(this.algorithm, key.data, iv);
        var encrypted = cipher.update(buffer);
        return Buffer.concat([iv, encrypted, cipher.final()]);
    }

    /**
     * Decrypts a buffer using the given password and salt.
     * @param {Buffer} buffer - The buffer to decrypt.
     * @param {String|{data:Buffer, salt:Buffer}} password - The password to derive a key from.
     * @param {String} [salt] - A random salt value.
     * @returns {Promise.<Buffer>}
     */
    async decryptBuffer(buffer, password, salt) {
        //validations & escapes
        if (buffer === null) {
            return null;
        } else if (Buffer.isBuffer(buffer) === false) {
            throw new Error('The "buffer" parameter argument must be a Buffer instance.');
        }
        if (!password) {
            throw new Error('A "password" paramater argument is required.');
        } else if (!password.data && !password.salt && typeof password !== 'string') {
            throw new Error('A "password" paramater argument must be a string or pbkdf2 derived key.');
        }
        if (salt && typeof salt !== 'string') {
            throw new Error('The "salt" parameter argument must be a string if specified.');
        }
        this._validateProperties();
        //decrypt the data
        let key = null;
        if (password.data && password.salt) {
            key = password;
            if (typeof salt !== 'undefined') {
                throw new Error('The "salt" parameter cannot be used when providing a pbkdf2 derived key.');
            }
        } else {
            key = await this.pbkdf2Key(password, salt);
        }
        let iv = buffer.slice(0, 16);
        let encrypted = buffer.slice(16);
        var decipher = crypto.createCipheriv(this.algorithm, key.data, iv);
        var decrypted = decipher.update(encrypted);
        return Buffer.concat([decrypted, decipher.final()]);
    }

    /**
     * Creates a message digest of the input text using the current hashing algorithm.
     * @param {String} text - The text to digest.
     * @param {String} [salt] - A random salt value.
     * @returns {String}
     */
    async hashText(text, salt) {
        if (text === null) {
            return null;
        }
        let digest = await this.hashBuffer(Buffer.from(text, this.encoding), salt);
        return digest.toString(this.outputEncoding);
    }

    /**
     * Creates a message digest of the input buffer using the current hashing algorithm.
     * @param {Buffer} buffer - The buffer to digest.
     * @param {String} [salt] - A random salt value.
     * @returns {Buffer}
     */
    async hashBuffer(buffer, salt) {
        //validations & escapes
        if (buffer === null) {
            return null;
        } else if (Buffer.isBuffer(buffer) === false) {
            throw new Error('The "buffer" parameter argument must be a Buffer instance.');
        }
        if (salt && typeof salt !== 'string') {
            throw new Error('The "salt" parameter argument must be a string if specified.');
        }
        this._validateProperties();
        //create a message digest
        let message = Buffer.concat([buffer, Buffer.from(salt || '', this.encoding)]);
        let hash = crypto.createHash(this.hashAlgorithm);
        return hash
            .update(message)
            .digest();
    }

    /**
     * Creates a message digest of the input text using the current hashing algorithm.
     * @param {String} filePath - The file path pointing to the file to hash.
     * @param {String} [salt] - A random salt value.
     * @returns {Buffer}
     */
    async hashFile(filePath, salt) {
        if (salt && typeof salt !== 'string') {
            throw new Error('The "salt" parameter argument must be a string if specified.');
        }
        return new Promise((resolve, reject) => {
            let hash = crypto.createHash(this.hashAlgorithm);
            try {
                let s = fs.ReadStream(filePath);
                s.on('data', function (data) {
                    hash.update(data);
                });
                s.on('end', function () {
                    if (salt) {
                        hash.update(Buffer.from(salt || '', this.encoding));
                    }
                    return resolve(hash.digest());
                });
            } catch (error) {
                return reject(error);
            }
        });
    }

    /**
     * Returns the signature of text using the given secret as a key with the hash algorithm.
     * @param {String} text - The text of data to sign.
     * @param {String|Buffer} secret - The secret to used as a key for the signature generation.
     * @returns {String}
     */
    async signText(text, secret) {
        if (text === null) {
            return null;
        }
        let sig = await this.signBuffer(Buffer.from(text, this.encoding), secret);
        return sig.toString(this.outputEncoding);
    }

    /**
     * Verifies the signature of a given text and secret and returns a boolean indicating success.
     * @param {String} text - The buffer of data that was signed.
     * @param {String|Buffer} secret - The secret that was used as a key for the signature generation.
     * @param {String} signature - The signature expected.
     * @returns {Boolean}
     */
    async verifyText(text, secret, signature) {
        if (text === null) {
            return null;
        }
        return this.verifyBuffer(Buffer.from(text, this.encoding), secret, Buffer.from(signature, this.outputEncoding));
    }

    /**
     * Returns the signature of a buffer using the given secret as a key with the hash algorithm.
     * @param {Buffer} buffer - The buffer of data to sign.
     * @param {String|Buffer} secret - The secret to used as a key for the signature generation.
     * @returns {Buffer}
     */
    async signBuffer(buffer, secret) {
        return crypto.createHmac(this.hashAlgorithm, secret)
            .update(buffer)
            .digest();
    }

    /**
     * Verifies the signature of a given buffer and secret and returns a boolean indicating success.
     * @param {Buffer} buffer - The buffer of data that was signed.
     * @param {String|Buffer} secret - The secret that was used as a key for the signature generation.
     * @param {Buffer} signature - The signature expected.
     * @returns {Boolean}
     */
    async verifyBuffer(buffer, secret, signature) {
        let sig = await this.signBuffer(buffer, secret);
        if (sig.byteLength !== signature.byteLength) {
            return false;
        }
        return crypto.timingSafeEqual(sig, signature);
    }

    /**
     * Returns a random string of text at or between the specified min and max length.
     * @param {Number} min - The minimum length of the string.
     * @param {Number} max - The maximum length of the string.
     * @returns {Buffer}
     */
    randomText(min, max) {
        let len = Math.floor(Math.random() * (max + 1 - min) + min);
        return crypto.randomBytes(max).toString('base64').substr(0, len);
    }

    /**
     * Returns a buffer of a random size at or between the specified min and max length, populated with random data.
     * @param {Number} min - The minimum byte length of the buffer.
     * @param {Number} max - The maximum byte length of the buffer.
     * @returns {Buffer}
     */
    randomBuffer(min, max) {
        let len = Math.floor(Math.random() * (max + 1 - min) + min);
        return crypto.randomBytes(len);
    }

}

export default Cryptography;