'use strict';

const { test } = require('tap');
const { crypt, verify } = require('..');
const { sha2Crypt } = require('../lib/sha2');
const { parseMagicSalt, to64 } = require('../lib/utils');

// We conditionnally execute this test as it can take more than 4 hours to complete
if (!process.env.FAST_CRYPT === 'true') {
  test('It should apply a maximum of 999,999,999 rounds when the provided rounds number is > 999,999,999', async (t) => {
    t.test('when using `sha256-crypt` algorithm', async (t) => {
      t.plan(3);

      const password = 'password';
      const salt = '$5$rounds=1000000000$roundstoohigh';
      const hash = '$5$rounds=999999999$roundstoohigh$Cvwk5TfVuI0UvXgZpr2vM4xs2Qn6.1fponaHP90Kcz.';

      const output = crypt(password, salt);

      t.equal(output, hash);
      t.equal(verify(password, hash), true);
      t.equal(output.slice(0, output.lastIndexOf('$')), '$5$rounds=999999999$roundstoohigh');
    });

    t.test('when using `sha512-crypt` algorithm', async (t) => {
      t.plan(3);

      const password = 'password';
      const salt = '$6$rounds=1000000000$roundstoohigh';
      const hash = '$6$rounds=999999999$roundstoohigh$K.Pe9SXf5yLP8K3brhbA4gDSXeXPKfqXkoatQeeyTm53ZAGUeTesrEfXM9RxdUXTyvc/0LCpaoTNqu2w.OJ8F/';

      const output = crypt(password, salt);

      t.equal(output, hash);
      t.equal(verify(password, hash), true);
      t.equal(output.slice(0, output.lastIndexOf('$')), '$6$rounds=999999999$roundstoohigh');
    });
  });
}

test('It should generate a 16 chars salt if the user does not provide one', async (t) => {
  t.test('when using `sha256-crypt`', async (t) => {
    t.plan(2);

    const output = crypt('password', '$5');
    const magic = output.slice(0, output.lastIndexOf('$'));

    t.equal(/^\$5\$[/.a-zA-Z0-9]+/s.test(magic), true);
    t.equal(magic.slice(1).split('$')[1].length, 16);
  });

  t.test('when using `sha512-crypt`', async (t) => {
    t.plan(2);

    const output = crypt('password', '$6');
    const magic = output.slice(0, output.lastIndexOf('$'));

    t.equal(/^\$6\$[/.a-zA-Z0-9]+/s.test(magic), true);
    t.equal(magic.slice(1).split('$')[1].length, 16);
  });

  t.test('when using `sha256-crypt and defining a round trip number`', async (t) => {
    t.plan(2);

    const output = crypt('password', '$5$rounds=10000');
    const magic = output.slice(0, output.lastIndexOf('$'));

    t.equal(/^\$5\$[/.a-zA-Z0-9]+/s.test(magic), true);
    t.equal(magic.slice(1).split('$')[2].length, 16);
  });

  t.test('when using `sha512-crypt and defining a round trip number`', async (t) => {
    t.plan(2);

    const output = crypt('password', '$6$rounds=10000');
    const magic = output.slice(0, output.lastIndexOf('$'));

    t.equal(/^\$6\$[/.a-zA-Z0-9]+/s.test(magic), true);
    t.equal(magic.slice(1).split('$')[2].length, 16);
  });
});

test('It should throw when the provided magic salt is malformed', async (t) => {
  t.plan(2);

  try {
    crypt('password', '$5$rounds=5000$salt$invalid_magic_salt');
  } catch (err) {
    t.ok(err);
    t.equal(err.message, 'Invalid salt string');
  }
});

test('It should throw when the provided salt contains forbidden characters', async (t) => {
  t.plan(2);

  try {
    crypt('password', '$5$forbidden-char');
  } catch (err) {
    t.ok(err);
    t.equal(err.message, 'Invalid salt string');
  }
});

test('It should throw when trying to use an unsupported algorithm', async (t) => {
  t.test('when using public crypt method', async (t) => {
    t.plan(2);

    try {
      crypt('password', '$unknown_algorithm');
    } catch (err) {
      t.ok(err);
      t.equal(err.message, 'Only sha256-crypt and sha512-crypt algorithms are supported');
    }
  });

  const sha2UnsupportedAlgorithms = [null, undefined, 'scrypt'];

  for (const algorithm of sha2UnsupportedAlgorithms) {
    t.test(`inside the internal private sha2Crypt() method with the algorithm option set to '${algorithm}'`, async (t) => {
      t.plan(2);

      try {
        sha2Crypt({ algorithm, password: 'password' });
      } catch (err) {
        t.ok(err);
        t.equal(err.message, `Unknown algorithm '${algorithm}', only sha256 and sha512 algorithms are supported`);
      }
    });
  }
});

test('It should correctly parse the magic salt', async (t) => {
  t.test('when using the internal private parseMagicSalt() method with the `sha256-crypt` algorithm', async (t) => {
    t.plan(3);

    const magicSalt = '$5$rounds=1000000000$roundstoohigh';
    const { algorithm, rounds, salt } = parseMagicSalt(magicSalt);

    t.equal(algorithm, 'sha256');
    t.equal(rounds, 999999999);
    t.equal(salt, 'roundstoohigh');
  });

  t.test('when using the internal private parseMagicSalt() method with the `sha512-crypt` algorithm', async (t) => {
    t.plan(3);

    const magicSalt = '$6$rounds=1000000000$roundstoohigh';
    const { algorithm, rounds, salt } = parseMagicSalt(magicSalt);

    t.equal(algorithm, 'sha512');
    t.equal(rounds, 999999999);
    t.equal(salt, 'roundstoohigh');
  });
});

test('It should throw on bad `to64()` options :', async (t) => {
  t.test('when `data` is not a buffer', async (t) => {
    t.plan(1);

    t.throws(() => to64('not a buffer', [0, 12]), 'data must be a buffer');
  });

  t.test('when `blocksOrder` is not an array of integers', async (t) => {
    t.plan(1);

    t.throws(
      () => to64(Buffer.alloc(16), 'not an array of integers'),
      'blocksOrder must be an array of integers');
  });
});
