import Cryptography from './cryptography.js';

const salts = [null, '', 'abc123'];
const algorithms = [null, 'aes-128-ctr', 'aes-192-ctr', 'aes-256-ctr'];
const hashAlgorithms = [null, 'ripemd160', 'sha256', 'sha384', 'sha512', 'whirlpool'];
const encodings = [null, 'utf8', 'ascii'];
const outputEncodings = [null, 'base64', 'hex'];
const passwords = ['short', 'longerpassword', 'c0MPl3x_PAS5W0rd:%@&'];

test('Cryptography: constructs ok.', () => {
    expect(() => { new Cryptography(); }).not.toThrow();
    for (let algorithm of algorithms) {
        for (let hashAlgorithm of hashAlgorithms) {
            for (let encoding of encodings) {
                for (let outputEncoding of outputEncodings) {
                    expect(() => { new Cryptography(algorithm, hashAlgorithm, encoding, outputEncoding); }).not.toThrow();
                    let c = new Cryptography(algorithm, hashAlgorithm, encoding, outputEncoding);
                    expect(c.algorithm).toBe(algorithm || 'aes-256-ctr');
                    expect(c.encoding).toBe(encoding || 'utf8');
                    expect(c.outputEncoding).toBe(outputEncoding || 'base64');
                }
            }
        }
    }
});

describe('buffer encryption & decryption', () => {
    let data = [Buffer.from('test 1234')];
    for (let algorithm of algorithms) {
        if (algorithm !== null) {
            for (let encoding of encodings) {
                if (encoding !== null) {
                    for (let outputEncoding of outputEncodings) {
                        if (outputEncoding !== null) {
                            it(`using the "${algorithm}" algorithm, "${encoding}" encoding, and "${outputEncoding}" output encoding.`, async () => {
                                let c = new Cryptography(algorithm, null, encoding, outputEncoding);
                                for (let password of passwords) {
                                    for (let salt of salts) {
                                        for (let d of data) {
                                            let enc = await c.encryptBuffer(d, password, salt);
                                            await expect(c.decryptBuffer(enc, password, salt)).resolves.toBeInstanceOf(Buffer);
                                            let dec = await c.decryptBuffer(enc, password, salt);
                                            expect(d.equals(dec)).toBe(true);
                                        }
                                    }
                                }
                            });
                        }
                    }
                }
            }
        }
    }
});

describe('text encryption & decryption', () => {
    let data = ['', 'test123'];
    for (let algorithm of algorithms) {
        if (algorithm !== null) {
            for (let encoding of encodings) {
                if (encoding !== null) {
                    for (let outputEncoding of outputEncodings) {
                        if (outputEncoding !== null) {
                            it(`using the "${algorithm}" algorithm, "${encoding}" encoding, and "${outputEncoding}" output encoding.`, async () => {
                                let c = new Cryptography(algorithm, null, encoding, outputEncoding);
                                for (let password of passwords) {
                                    for (let salt of salts) {
                                        for (let d of data) {
                                            let enc = await c.encryptText(d, password, salt);
                                            await expect(c.decryptText(enc, password, salt)).resolves.not.toBeNull();
                                            let dec = await c.decryptText(enc, password, salt);
                                            expect(dec).toEqual(d);
                                        }
                                    }
                                }
                            });
                        }
                    }
                }
            }
        }
    }
});

describe('buffer hashing', () => {
    for (let hashAlgorithm of hashAlgorithms) {
        if (hashAlgorithm !== null) {
            for (let encoding of encodings) {
                if (encoding !== null) {
                    for (let outputEncoding of outputEncodings) {
                        if (outputEncoding !== null) {
                            let c = new Cryptography(null, hashAlgorithm, encoding, outputEncoding);
                            it(`reliable digest using the "${hashAlgorithm}" hash algorithm, "${encoding}" encoding, and "${outputEncoding}" output encoding.`, async () => {
                                let digest = await c.hashBuffer(Buffer.from('test123', encoding), 'saltABC');
                                let digest2 = await c.hashBuffer(Buffer.from('test123', encoding), 'saltABC');
                                expect(Buffer.compare(digest, digest2)).toBe(0);
                                digest = await c.hashBuffer(Buffer.from('test123', encoding), '');
                                digest2 = await c.hashBuffer(Buffer.from('test123', encoding), null);
                                expect(Buffer.compare(digest, digest2)).toBe(0);
                            });
                        }
                    }
                }
            }
        }
    }
});

describe('text hashing', () => {
    for (let hashAlgorithm of hashAlgorithms) {
        if (hashAlgorithm !== null) {
            for (let encoding of encodings) {
                if (encoding !== null) {
                    for (let outputEncoding of outputEncodings) {
                        if (outputEncoding !== null) {
                            let c = new Cryptography(null, hashAlgorithm, encoding, outputEncoding);
                            it(`reliable digest using the "${hashAlgorithm}" hash algorithm, "${encoding}" encoding, and "${outputEncoding}" output encoding.`, async () => {
                                let digest = await c.hashText('test123', 'saltABC');
                                let digest2 = await c.hashText('test123', 'saltABC');
                                expect(digest).toEqual(digest2);
                                digest = await c.hashText('test123', '');
                                digest2 = await c.hashText('test123', null);
                                expect(digest).toEqual(digest2);
                            });
                        }
                    }
                }
            }
        }
    }
});

describe('file hashing', () => {
    for (let hashAlgorithm of hashAlgorithms) {
        if (hashAlgorithm !== null) {
            for (let encoding of encodings) {
                if (encoding !== null) {
                    for (let outputEncoding of outputEncodings) {
                        if (outputEncoding !== null) {
                            let c = new Cryptography(null, hashAlgorithm, encoding, outputEncoding);
                            it(`reliable digest using the "${hashAlgorithm}" hash algorithm, "${encoding}" encoding, and "${outputEncoding}" output encoding.`, async () => {
                                let digest = await c.hashFile('test/crypto-test.json', 'saltABC');
                                let digest2 = await c.hashFile('test/crypto-test.json', 'saltABC');
                                expect(digest).toEqual(digest2);
                                digest = await c.hashFile('test/crypto-test.json', '');
                                digest2 = await c.hashFile('test/crypto-test.json', null);
                                expect(digest).toEqual(digest2);
                            });
                        }
                    }
                }
            }
        }
    }
});

describe('buffer signature and verification', () => {
    for (let hashAlgorithm of hashAlgorithms) {
        if (hashAlgorithm !== null) {
            for (let encoding of encodings) {
                if (encoding !== null) {
                    for (let outputEncoding of outputEncodings) {
                        if (outputEncoding !== null) {
                            let c = new Cryptography(null, hashAlgorithm, encoding, outputEncoding);
                            let buf = Buffer.from('test123', encoding);
                            let key = 'keyABC';
                            it(`generates signature using  "${hashAlgorithm}" hash algorithm, "${encoding}" encoding, and "${outputEncoding}" output encoding.`, async () => {
                                let sig = await c.signBuffer(buf, key);
                                expect(Buffer.isBuffer(sig)).toBe(true);
                            });
                            it(`verifies signature using  "${hashAlgorithm}" hash algorithm, "${encoding}" encoding, and "${outputEncoding}" output encoding.`, async () => {
                                let sig = await c.signBuffer(buf, key);
                                let verified = await c.verifyBuffer(buf, key, sig);
                                expect(verified).toBe(true);
                                verified = await c.verifyBuffer(buf, 'bad_key987', sig);
                                expect(verified).toBe(false);
                                verified = await c.verifyBuffer(buf, key, Buffer.from('hello'));
                                expect(verified).toBe(false);
                            });
                        }
                    }
                }
            }
        }
    }
});

describe('text signature and verification', () => {
    for (let hashAlgorithm of hashAlgorithms) {
        if (hashAlgorithm !== null) {
            for (let encoding of encodings) {
                if (encoding !== null) {
                    for (let outputEncoding of outputEncodings) {
                        if (outputEncoding !== null) {
                            let c = new Cryptography(null, hashAlgorithm, encoding, outputEncoding);
                            let text = 'test123';
                            let key = 'keyABC';
                            it(`generates signature using  "${hashAlgorithm}" hash algorithm, "${encoding}" encoding, and "${outputEncoding}" output encoding.`, async () => {
                                let sig = await c.signText(text, key);
                                expect(typeof sig).toBe('string');
                                expect(sig.length).toBeGreaterThan(0);
                            });
                            it(`verifies signature using  "${hashAlgorithm}" hash algorithm, "${encoding}" encoding, and "${outputEncoding}" output encoding.`, async () => {
                                let sig = await c.signText(text, key);
                                let verified = await c.verifyText(text, key, sig);
                                expect(verified).toBe(true);
                                verified = await c.verifyText(text, 'bad_key987', sig);
                                expect(verified).toBe(false);
                                verified = await c.verifyText(text, key, 'hello');
                                expect(verified).toBe(false);
                            });
                        }
                    }
                }
            }
        }
    }
});

describe('random buffers', () => {
    let c = new Cryptography();
    it('generates a random buffer of data between the specified byte length', async () => {
        for (let x = 0; x < 1000; x++) {
            let r = c.randomBuffer(x, 1001);
            expect(Buffer.isBuffer(r)).toBe(true);
            expect(r.byteLength).toBeGreaterThanOrEqual(x);
            expect(r.byteLength).toBeLessThanOrEqual(1001);
        }
    });
    it('generates random text between the specified length', async () => {
        for (let x = 0; x < 1000; x++) {
            let r = c.randomText(x, 1001);
            expect(typeof r).toBe('string');
            expect(r.length).toBeGreaterThanOrEqual(x);
            expect(r.length).toBeLessThanOrEqual(1001);
        }
    });
});
