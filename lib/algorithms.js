import HmacSHA256 from 'crypto-js/hmac-sha256';
import HmacSHA384 from 'crypto-js/hmac-sha384';
import HmacSHA512 from 'crypto-js/hmac-sha512';
import { Crypt } from 'hybrid-crypto-js';
import * as forge from 'node-forge'

const crypt = new Crypt();

function RS256(message, key){
  const forgePrivateKey = forge.pki.privateKeyFromPem(key);
  const forgePublicKey = forge.pki.setRsaPublicKey(forgePrivateKey.n, forgePrivateKey.e);
  const publicKey = forge.pki.publicKeyToPem(forgePublicKey);
  const result = crypt.encrypt(publicKey, message, key);
  const parsedResult = JSON.parse(result);
  return {
    toString: () => parsedResult.cipher
  }
}

const mapping = {
  HS256: HmacSHA256,
  HS384: HmacSHA384,
  HS512: HmacSHA512,
  RS256
};

export const supportedAlgorithms = Object.keys(mapping);

export default mapping;
