'use strict';

const CRYPT_SHA2_ROUNDS_MIN = 1000;
const CRYPT_SHA2_ROUNDS_DEFAULT = 5000;
const CRYPT_SHA2_ROUNDS_MAX = 999999999;

const CRYPT_SHA2_SALT_LENGTH = 16;

const CRYPT_INVALID_SALT_CHARACTERS = /[^./a-zA-Z0-9]/;

// The order has its importance here
const DICTIONNARY = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

/**
 * Crypt compliant random salt generator
 *
 * @example <caption>Example: generates a 16 chars salt</caption>
 * const { randomCryptSalt } = require('./lib/utils');
 *
 * const salt = randomCryptSalt(16);
 * // it will output a 16 chars salt. E.g.: '3gFp0rp6BSYNPCaC'
 * console.log(salt);
 *
 * @param {number} length - the generated salt length
 *
 * @returns {string} Returns a random generated salt
 */
function randomCryptSalt (length) {
  const salt = [];

  for (let i = 0; i < length; i++) {
    salt.push(DICTIONNARY.charAt(Math.floor(Math.random() * DICTIONNARY.length)));
  }

  return salt.join('');
}

/**
 * Magic salt parser
 *
 * @param {string} magic
 * @returns {{ algorithm: string; prefix: number|string; rounds: number; salt: string}}
 */
function parseMagicSalt (magic) {
  const params = magic.slice(1).split('$');

  const prefix = parseInt(params[0]);

  if (
    params.length < 1
    || params.length > 3
  ) {
    throw new Error('Invalid salt string');
  }

  if (
    // SHA256-CRYPT
    prefix !== 5
    // SHA512-CRYPT
    && prefix !== 6
  ) {
    throw new Error('Only sha256-crypt and sha512-crypt algorithms are supported');
  }

  const algorithm = prefix === 5 ? 'sha256' : 'sha512';

  const rounds = params.length === 3 || (params.length === 2 && /^rounds=/s.test(params[1]))
    ? parseInt(params[1].replace(/^rounds=/, '')) < CRYPT_SHA2_ROUNDS_MIN
      ? CRYPT_SHA2_ROUNDS_MIN
      : parseInt(params[1].replace(/^rounds=/, '')) > CRYPT_SHA2_ROUNDS_MAX
        ? CRYPT_SHA2_ROUNDS_MAX
        : parseInt(params[1].replace(/^rounds=/, ''))
    : CRYPT_SHA2_ROUNDS_DEFAULT;

  const salt = params.length === 1 || (params.length === 2 && /^rounds=/s.test(params[1]))
    ? randomCryptSalt(CRYPT_SHA2_SALT_LENGTH)
    : params.length === 3
      ? params[2].substring(0, CRYPT_SHA2_SALT_LENGTH)
      : params[1].substring(0, CRYPT_SHA2_SALT_LENGTH);

  if (salt.match(CRYPT_INVALID_SALT_CHARACTERS)) {
    throw new Error('Invalid salt string');
  }

  return {
    algorithm,
    prefix,
    rounds,
    salt
  };
}

/**
 * @param {Buffer} data
 * @param {Number[]} blocksOrder
 */
function to64 (data, blocksOrder) {
  if (!Buffer.isBuffer(data)) {
    throw new Error('data must be a buffer');
  }

  if (!Array.isArray(blocksOrder)) {
    throw new Error('blocksOrder must be an array of integers');
  }

  const hash64 = [];

  for (let index = 0; index < data.length; index += 3) {
    const buffer = Buffer.alloc(3);

    buffer[0] = data[blocksOrder[index]];
    buffer[1] = data[blocksOrder[index + 1]];
    buffer[2] = data[blocksOrder[index + 2]];

    // 1st
    hash64.push(DICTIONNARY.charAt(
      // (base 16) 0x3f === (base 2) 00111111 === (base 10) 63
      buffer[0] & parseInt('0x3f')
    ));

    // 2nd
    hash64.push(DICTIONNARY.charAt(
      // (base 16) 0xc0 === (base 2) 11000000 === (base 10) 192
      // (base 16) 0xf === (base 2) 00001111 === (base 10) 15
      (buffer[0] & parseInt('0xc0')) >>> 6 | (buffer[1] & parseInt('0xf')) << 2
    ));

    // 3rd
    hash64.push(DICTIONNARY.charAt(
      // (base 16) 0xf0 === (base 2) 11110000 === (base 10) 240
      // (base 16) 0x3 === (base 2) 00000011 === (base 10) 3
      (buffer[1] & parseInt('0xf0')) >>> 4 | (buffer[2] & parseInt('0x3')) << 4
    ));

    // 4th
    hash64.push(DICTIONNARY.charAt(
      // (base 16) 0xfc === (base 2) 11111100 === (base 10) 252
      (buffer[2] & parseInt('0xfc')) >>> 2
    ));
  }

  return hash64.join('');
}

module.exports = {
  DICTIONNARY,
  parseMagicSalt,
  randomCryptSalt,
  to64
};
