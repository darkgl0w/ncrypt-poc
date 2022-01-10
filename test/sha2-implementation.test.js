'use strict';

const { test } = require('tap');
const { crypt, verify } = require('..');

test('It should pass the `sha256-crypt` reference implementation test suite', async (t) => {
  t.test('It should generate and verify a hash when a salt is provided', async (t) => {
    t.plan(2);

    const password = 'Hello world!';
    const salt = '$5$saltstring';
    const hash = '$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5';

    const output = crypt(password, salt);

    t.equal(output, hash);
    t.equal(verify(password, hash), true);
  });

  t.test('It should truncate the salt to 16 chars and apply the specified number of rounds', async (t) => {
    t.plan(2);

    const password = 'Hello world!';
    const salt = '$5$rounds=10000$saltstringsaltstring';
    const hash = '$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA';

    const output = crypt(password, salt);

    t.equal(output, hash);
    t.equal(verify(password, hash), true);
  });

  t.test('It should truncate the salt to 16 chars and apply the default number of rounds', async (t) => {
    t.plan(2);

    const password = 'This is just a test';
    const salt = '$5$rounds=5000$toolongsaltstring';
    const hash = '$5$rounds=5000$toolongsaltstrin$Un/5jzAHMgOGZ5.mWJpuVolil07guHPvOW8mGRcvxa5';

    const output = crypt(password, salt);

    t.equal(output, hash);
    t.equal(verify(password, hash), true);
  });

  t.test('It should generate and verify a hash when a long salt and passwords are provided', async (t) => {
    t.plan(2);

    const password = 'a very much longer text to encrypt.  This one even stretches over morethan one line.';
    const salt = '$5$rounds=1400$anotherlongsaltstring';
    const hash = '$5$rounds=1400$anotherlongsalts$Rx.j8H.h8HjEDGomFU8bDkXm3XIUnzyxf12oP84Bnq1';

    const output = crypt(password, salt);

    t.equal(output, hash);
    t.equal(verify(password, hash), true);
  });

  t.test('It should generate and verify a hash when a short salt and a long password are provided', async (t) => {
    t.plan(2);

    const password = 'we have a short salt string but not a short password';
    const salt = '$5$rounds=77777$short';
    const hash = '$5$rounds=77777$short$JiO1O3ZpDAxGJeaDIuqCoEFysAe1mZNJRs3pw0KQRd/';

    const output = crypt(password, salt);

    t.equal(output, hash);
    t.equal(verify(password, hash), true);
  });

  t.test('It should generate and verify a hash when a short password and salt are provided', async (t) => {
    t.plan(2);

    const password = 'a short string';
    const salt = '$5$rounds=123456$asaltof16chars..';
    const hash = '$5$rounds=123456$asaltof16chars..$gP3VQ/6X7UUEW3HkBn2w1/Ptq2jxPyzV/cZKmF/wJvD';

    const output = crypt(password, salt);

    t.equal(output, hash);
    t.equal(verify(password, hash), true);
  });

  t.test('It should apply a minimum of 1000 rounds when the provided rounds number is < 1000', async (t) => {
    t.plan(2);

    const password = 'the minimum number is still observed';
    const salt = '$5$rounds=10$roundstoolow';
    const hash = '$5$rounds=1000$roundstoolow$yfvwcWrQ8l/K0DAWyuPMDNHpIVlTQebY9l/gL972bIC';

    const output = crypt(password, salt);

    t.equal(output, hash);
    t.equal(verify(password, hash), true);
  });
});

test('It should pass the `sha512-crypt` reference implementation test suite', async (t) => {
  t.test('It should generate and verify a hash when a salt is provided', async (t) => {
    t.plan(2);

    const password = 'Hello world!';
    const salt = '$6$saltstring';
    const hash = '$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1';

    const output = crypt(password, salt);

    t.equal(output, hash);
    t.equal(verify(password, hash), true);
  });

  t.test('It should truncate the salt to 16 chars and apply the specified number of rounds', async (t) => {
    t.plan(2);

    const password = 'Hello world!';
    const salt = '$6$rounds=10000$saltstringsaltstring';
    const hash = '$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v.';

    const output = crypt(password, salt);

    t.equal(output, hash);
    t.equal(verify(password, hash), true);
  });

  t.test('It should truncate the salt to 16 chars and apply the default number of rounds', async (t) => {
    t.plan(2);

    const password = 'This is just a test';
    const salt = '$6$rounds=5000$toolongsaltstring';
    const hash = '$6$rounds=5000$toolongsaltstrin$lQ8jolhgVRVhY4b5pZKaysCLi0QBxGoNeKQzQ3glMhwllF7oGDZxUhx1yxdYcz/e1JSbq3y6JMxxl8audkUEm0';

    const output = crypt(password, salt);

    t.equal(output, hash);
    t.equal(verify(password, hash), true);
  });

  t.test('It should generate and verify a hash when a long salt and passwords are provided', async (t) => {
    t.plan(2);

    const password = 'a very much longer text to encrypt.  This one even stretches over morethan one line.';
    const salt = '$6$rounds=1400$anotherlongsaltstring';
    const hash = '$6$rounds=1400$anotherlongsalts$POfYwTEok97VWcjxIiSOjiykti.o/pQs.wPvMxQ6Fm7I6IoYN3CmLs66x9t0oSwbtEW7o7UmJEiDwGqd8p4ur1';

    const output = crypt(password, salt);

    t.equal(output, hash);
    t.equal(verify(password, hash), true);
  });

  t.test('It should generate and verify a hash when a short salt and a long password are provided', async (t) => {
    t.plan(2);

    const password = 'we have a short salt string but not a short password';
    const salt = '$6$rounds=77777$short';
    const hash = '$6$rounds=77777$short$WuQyW2YR.hBNpjjRhpYD/ifIw05xdfeEyQoMxIXbkvr0gge1a1x3yRULJ5CCaUeOxFmtlcGZelFl5CxtgfiAc0';

    const output = crypt(password, salt);

    t.equal(output, hash);
    t.equal(verify(password, hash), true);
  });

  t.test('It should generate and verify a hash when a short password and salt are provided', async (t) => {
    t.plan(2);

    const password = 'a short string';
    const salt = '$6$rounds=123456$asaltof16chars..';
    const hash = '$6$rounds=123456$asaltof16chars..$BtCwjqMJGx5hrJhZywWvt0RLE8uZ4oPwcelCjmw2kSYu.Ec6ycULevoBK25fs2xXgMNrCzIMVcgEJAstJeonj1';

    const output = crypt(password, salt);

    t.equal(output, hash);
    t.equal(verify(password, hash), true);
  });

  t.test('It should apply a minimum of 1000 rounds when the provided rounds number is < 1000', async (t) => {
    t.plan(2);

    const password = 'the minimum number is still observed';
    const salt = '$6$rounds=10$roundstoolow';
    const hash = '$6$rounds=1000$roundstoolow$kUMsbe306n21p9R.FRkW3IGn.S9NPN0x50YhH1xhLsPuWGsUSklZt58jaTfF4ZEQpyUNGc0dqbpBYYBaHHrsX.';

    const output = crypt(password, salt);

    t.equal(output, hash);
    t.equal(verify(password, hash), true);
  });
});
