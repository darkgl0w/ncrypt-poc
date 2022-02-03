'use strict';

const { timingSafeEqual } = require('crypto');
const { sha2Crypt } = require('./lib/sha2');
const { parseMagicSalt } = require('./lib/utils');

/**
 * @param {string} password - The password string.
 * @param {string} magic - The salt string.
 */
function crypt (password, magic) {
  const { algorithm, prefix, rounds, salt } = parseMagicSalt(magic);
  const result = [''];

  result.push(prefix);
  if (magic.slice(1).split('$').length === 3 || rounds !== 5000) result.push(`rounds=${rounds}`);
  result.push(salt);
  result.push(sha2Crypt({ algorithm, password, rounds, salt }));

  return result.join('$');
}

/**
 * @param {string} password - The password string.
 * @param {string} hash - The password hash to verify.
 */
function verify (password, hash) {
  const salt = hash.slice(0, hash.lastIndexOf('$'));

  const hashBuffer = Buffer.from(hash, 'utf8');
  const output = Buffer.from(crypt(password, salt), 'utf8');

  return timingSafeEqual(hashBuffer, output);
}

module.exports = { crypt, verify };
