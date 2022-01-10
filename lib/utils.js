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
    prefix !== 5
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
    rounds,
    salt
  };
}

module.exports = {
  DICTIONNARY,
  randomCryptSalt,
  parseMagicSalt
};
