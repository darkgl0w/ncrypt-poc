'use strict';

const { createHash } = require('crypto');
const { to64 } = require('./utils');

// #1, #2, #3: byte number in group
const blocksOrder = {
  sha256: [
    20, 10, 0,
    11, 1, 21,
    2, 22, 12,
    23, 13, 3,
    14, 4, 24,
    5, 25, 15,
    26, 16, 6,
    17, 7, 27,
    8, 28, 18,
    29, 19, 9,
    30, 31
  ],
  sha512: [
    42, 21, 0,
    1, 43, 22,
    23, 2, 44,
    45, 24, 3,
    4, 46, 25,
    26, 5, 47,
    48, 27, 6,
    7, 49, 28,
    29, 8, 50,
    51, 30, 9,
    10, 52, 31,
    32, 11, 53,
    54, 33, 12,
    13, 55, 34,
    35, 14, 56,
    57, 36, 15,
    16, 58, 37,
    38, 17, 59,
    60, 39, 18,
    19, 61, 40,
    41, 20, 62,
    63
  ]
};

/**
 * sha256 and sha512 checksum hash generator following the Modular Crypt Format
 *
 * @param {object} options - options
 * @param {string} options.password - the password to encrypt
 * @param {'sha256'|'sha512'} options.algorithm
 * @param {number} options.rounds
 * @param {string} options.salt
 */
function sha2Crypt ({ algorithm, password, rounds, salt }) {
  if (
    !algorithm
    || !(algorithm === 'sha256' || algorithm === 'sha512')
  ) {
    throw new Error(`Unknown algorithm '${algorithm}', only sha256 and sha512 algorithms are supported`);
  }

  const passwordByteLength = Buffer.byteLength(password);
  const saltByteLength = Buffer.byteLength(salt);

  const digestSize = algorithm === 'sha256' ? 32 : 64;

  // step 1
  const A = createHash(algorithm)
    // step 2
    .update(password)
    // step 3
    .update(salt);

  // step 4
  const digestB = createHash(algorithm)
    // step 5
    .update(password)
    // step 6
    .update(salt)
    // step 7
    .update(password)
    // step 8
    .digest();

  // step 9
  for (let offset = 0; offset + digestSize < passwordByteLength; offset += digestSize) {
    A.update(digestB);
  }

  // step 10
  A.update(digestB.slice(0, passwordByteLength % digestSize));

  // step 11
  passwordByteLength.toString(2)
    .split('')
    .reverse()
    .forEach(bit => {
      A.update(
        bit !== '0'
          // step 11 - a
          ? digestB
          // step 11 - b
          : password
      );
    });

  // step 12
  const digestA = A.digest();

  // step 13
  const DP = createHash(algorithm);

  // step 14
  for (let i = 0; i < passwordByteLength; i++) {
    DP.update(password);
  }

  // step 15
  const digestDP = DP.digest();

  // step 16
  const P = Buffer.alloc(passwordByteLength);

  // step 16 - a
  for (let offset = 0; offset + digestSize < passwordByteLength; offset += digestSize) {
    P.set(digestDP, offset);
  }

  // step 16 - b
  P.set(
    digestDP.slice(0, passwordByteLength % digestSize),
    passwordByteLength - passwordByteLength % digestSize
  );

  // step 17
  const DS = createHash(algorithm);

  // step 18
  for (let i = 0; i < 16 + digestA[0]; i++) {
    DS.update(salt);
  }

  // step 19
  const digestDS = DS.digest();

  // step 20
  const S = Buffer.alloc(salt.length);

  // step 20 - a
  for (let offset = 0; offset + digestSize < saltByteLength; offset += digestSize) {
    /* istanbul ignore next - this path seems to never be taken */
    S.set(digestDS, offset);
  }

  // step 20 - b
  S.set(
    digestDS.slice(0, saltByteLength % digestSize),
    saltByteLength - saltByteLength % digestSize
  );

  // step 21
  const digestC = new Uint32Array(rounds)
    .reduce((previous, current, index) => {
      // step 21 - a
      const C = createHash(algorithm);

      index % 2 !== 0
        // step 21 - b
        ? C.update(P)
        // ste p 21 - c
        : C.update(previous);

      // step 21 - d
      if (index % 3 !== 0) C.update(S);

      // step 21 - e
      if (index % 7 !== 0) C.update(P);

      index % 2 !== 0
        // step 21 - f
        ? C.update(previous)
        // step 21 - g
        : C.update(P);

      // step 21 - h
      return C.digest();
    }, digestA);

  // step 22
  return to64(digestC, blocksOrder[algorithm]).slice(0, digestC.length === 32 ? -1 : -2);
}

module.exports = { sha2Crypt };
