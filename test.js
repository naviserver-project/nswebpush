// based on https://developers.google.com/web/updates/2016/03/web-push-encryption

const crypto = require('crypto');

// make fixed salt for testing
const salt = new Buffer(' WVGtEt/7tGKMNgqAeDvEPA==', 'base64');
console.log('Salt ' + salt.toString('base64'));

const serverECDH = crypto.createECDH('prime256v1');
// same as prime256v1_key.pem
serverECDH.setPrivateKey('9QHJ/t2xdxaivw3l3fOd815/BCJCM6vLksN4Pd5lVQg=', 'base64');
console.log('Server private base64: ' + serverECDH.getPrivateKey('base64'));
const serverPublicKey = serverECDH.getPublicKey();
console.log('Server public base64: ' + serverPublicKey.toString('base64'));
// From subscription:
const clientPublicKey = new Buffer('BNvOAPaPCCfpNCMR4AccTffxD8YMQbfIBWieLxgZE1qgU-YVVT5mOD7CaRRqg5ykA7_f8jm2VuOPZLvHn0moHas', 'base64');
const clientAuthSecret = new Buffer('4LLU4S9l1S9IrPTsQZkPqw', 'base64');

const sharedSecret = serverECDH.computeSecret(clientPublicKey);
console.log('Secret: ' + sharedSecret.toString('base64'));

// Simplified HKDF, returning keys up to 32 bytes long
function hkdf(salt, ikm, info, length) {
    if (length > 32) {
      throw new Error('Cannot return keys of more than 32 bytes, ${length} requested');
    }

    // Extract
    const keyHmac = crypto.createHmac('sha256', salt);
    keyHmac.update(ikm);
    const key = keyHmac.digest();

    // Expand
    const infoHmac = crypto.createHmac('sha256', key);
    infoHmac.update(info);
    // A one byte long buffer containing only 0x01
    const ONE_BUFFER = new Buffer(1).fill(1);
    infoHmac.update(ONE_BUFFER);
    return infoHmac.digest().slice(0, length);
  }

function createInfo(type, clientPublicKey, serverPublicKey) {
    const len = type.length;

    // The start index for each element within the buffer is:
    // value               | length | start    |
    // -----------------------------------------
    // 'Content-Encoding: '| 18     | 0        |
    // type                | len    | 18       |
    // nul byte            | 1      | 18 + len |
    // 'P-256'             | 5      | 19 + len |
    // nul byte            | 1      | 24 + len |
    // client key length   | 2      | 25 + len |
    // client key          | 65     | 27 + len |
    // server key length   | 2      | 92 + len |
    // server key          | 65     | 94 + len |
    // For the purposes of push encryption the length of the keys will
    // always be 65 bytes.
    const info = new Buffer(18 + len + 1 + 5 + 1 + 2 + 65 + 2 + 65);

    // The string 'Content-Encoding: ', as utf-8
    info.write('Content-Encoding: ');
    // The 'type' of the record, a utf-8 string
    info.write(type, 18);
    // A single null-byte
    info.write('\0', 18 + len);
    // The string 'P-256', declaring the elliptic curve being used
    info.write('P-256', 19 + len);
    // A single null-byte
    info.write('\0', 24 + len);
    // The length of the client's public key as a 16-bit integer
    info.writeUInt16BE(clientPublicKey.length, 25 + len);
    // Now the actual client public key
    clientPublicKey.copy(info, 27 + len);
    // Length of our public key
    info.writeUInt16BE(serverPublicKey.length, 92 + len);
    // The key itself
    serverPublicKey.copy(info, 94 + len);

    return info;
  }
  // make initial key material
  const authInfo = new Buffer('Content-Encoding: auth\0', 'utf8');
  console.log('authinfo ' + authInfo.toString('base64'));
  const ikm = hkdf(clientAuthSecret, sharedSecret, authInfo, 32);
  console.log('ikm ' + ikm.toString('base64'));

  // Derive the Content Encryption Key
  const contentEncryptionKeyInfo = createInfo('aesgcm', clientPublicKey, serverPublicKey);
  const contentEncryptionKey = hkdf(salt, ikm, contentEncryptionKeyInfo, 16);

  // Derive the Nonce
  const nonceInfo = createInfo('nonce', clientPublicKey, serverPublicKey);
  const nonce = hkdf(salt, ikm, nonceInfo, 12);

  console.log('Server ' + serverPublicKey.toString('base64'));
  console.log('Client ' + clientPublicKey.toString('base64'));
  console.log('Salt ' + salt.toString('base64'));
  console.log('Keyinfo ' + contentEncryptionKeyInfo.toString('base64'));
  console.log('Key ' + contentEncryptionKey.toString('base64'));
  console.log('nonce ' + nonce.toString('base64'));

  // testing hkdf
  var s = new Buffer('000102030405060708090a0b0c', 'hex');
  var se = new Buffer('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b', 'hex');
  var inf = new Buffer('f0f1f2f3f4f5f6f7f8f9', 'hex');
  console.log('expected: 3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf');
  console.log(hkdf(s, se, inf, 32).toString('hex'));

  //encryption
  const plaintext = new Buffer('Push notification payload!', 'utf8');
  //padding
  const paddingLength = 4078 - plaintext.length;
  console.log('paddinglength: ' + paddingLength);
  var padding = new Buffer(2 + paddingLength);
  // The buffer must be only zeros, except the length
  padding.fill(0);
  padding.writeUInt16BE(paddingLength, 0);
  const cipher = crypto.createCipheriv('id-aes128-GCM', contentEncryptionKey,
  nonce);

  const result = cipher.update(Buffer.concat([padding, plaintext]));
  console.log('Cypther result: ' + result.toString('base64'));
  cipher.final();

  // Append the auth tag to the result - https://nodejs.org/api/crypto.html#crypto_cipher_getauthtag
  const encrypted = Buffer.concat([result, cipher.getAuthTag()]);
  console.log('Authtag: ' + cipher.getAuthTag().toString('base64'));
  console.log('Authtag bytelength: ' + Buffer.byteLength(cipher.getAuthTag()));
  console.log('Encrypted: ' + encrypted.toString('base64'));
