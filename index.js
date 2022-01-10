'use strict';

const { timingSafeEqual } = require('crypto');
const { sha2Crypt } = require('./lib/sha2');
const { parseMagicSalt } = require('./lib/utils');

function crypt (password, magic) {
  const { algorithm, rounds, salt } = parseMagicSalt(magic);
  const result = [''];

  result.push(algorithm === 'sha256' ? 5 : 6);
  if (magic.slice(1).split('$').length === 3 || rounds !== 5000) result.push(`rounds=${rounds}`);
  result.push(salt);
  result.push(sha2Crypt(password, { algorithm, rounds, salt }));

  return result.join('$');
}

function verify (password, hash) {
  const salt = hash.slice(0, hash.lastIndexOf('$'));

  const hashBuffer = Buffer.from(hash, 'utf8');
  const output = Buffer.from(crypt(password, salt), 'utf8');

  return timingSafeEqual(hashBuffer, output);
}

module.exports = { crypt, verify };
