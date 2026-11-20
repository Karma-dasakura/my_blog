const { test } = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
const { response, security } = require('./helpers');
const { encrypt, decrypt, emailLookup } = require('../src/crypto');
const validate = require('../src/validate');

for (const [name, cookie, header, expected] of [
  ['missing both tokens', undefined, undefined, 403],
  ['missing header', 'abc', undefined, 403],
  ['missing cookie', undefined, 'abc', 403],
  ['different lengths', 'abc', 'abcd', 403],
  ['different values', 'abc', 'xyz', 403],
  ['matching tokens', 'abc', 'abc', 200],
]) test(`CSRF: ${name}`, () => {
  const res = response();
  let passed = false;
  security.requireCsrf({ method: 'POST', cookies: { csrf_token: cookie }, get: () => header }, res, () => { passed = true; });
  assert.equal(res.statusCode, expected);
  assert.equal(passed, expected === 200);
});
test('CSRF allows read-only requests without a token', () => {
  for (const method of ['GET', 'HEAD', 'OPTIONS']) {
    let passed = false;
    security.requireCsrf({ method }, response(), () => { passed = true; });
    assert.equal(passed, true);
  }
});
test('CSRF token generation uses independent 32-byte random tokens', () => {
  const a = response(); const b = response();
  security.setCsrfCookie({ cookies: {} }, a, () => {});
  security.setCsrfCookie({ cookies: {} }, b, () => {});
  assert.match(a.cookies.csrf_token.value, /^[a-f0-9]{64}$/);
  assert.notEqual(a.cookies.csrf_token.value, b.cookies.csrf_token.value);
  const existing = response();
  security.setCsrfCookie({ cookies: { csrf_token: 'existing' } }, existing, () => {});
  assert.deepEqual(existing.cookies, {});
});
test('Issued session is signed, expires, and uses protected cookie options', () => {
  const res = response();
  security.issueSession(res, { id: 7, role: 'author' });
  const { value, options } = res.cookies.session;
  const decoded = jwt.verify(value, process.env.JWT_SECRET, { algorithms: ['HS256'], issuer: 'ele201-myblog' });
  assert.equal(decoded.id, 7);
  assert.equal(decoded.exp - decoded.iat, 3600);
  assert.equal(options.httpOnly, true);
  assert.equal(options.path, '/');
  assert.equal(options.maxAge, 3600000);
});
test('Production session cookies require HTTPS', () => {
  const filename = require.resolve('../src/security');
  const cached = require.cache[filename];
  const previous = process.env.NODE_ENV;
  try {
    process.env.NODE_ENV = 'production';
    delete require.cache[filename];
    const production = require(filename);
    assert.equal(production.cookieOptions.secure, true);
    const res = response();
    production.setCsrfCookie({ cookies: {} }, res, () => {});
    assert.equal(res.cookies.csrf_token.options.secure, true);
  } finally {
    process.env.NODE_ENV = previous;
    require.cache[filename] = cached;
  }
});
test('AES-GCM round trip preserves Unicode and randomizes ciphertext', () => {
  const plaintext = 'Private story 🔒 नमस्ते';
  const a = encrypt(plaintext); const b = encrypt(plaintext);
  assert.equal(decrypt(a), plaintext);
  assert.notEqual(a, b);
  assert.ok(!a.includes(plaintext));
});
test('AES-GCM rejects tampered ciphertext', () => {
  const parts = encrypt('Private story').slice(3).split('.');
  const bytes = Buffer.from(parts[1], 'base64'); bytes[0] ^= 1;
  parts[1] = bytes.toString('base64');
  assert.throws(() => decrypt(`v1:${parts.join('.')}`));
});
test('AES-GCM rejects the wrong encryption key', () => {
  const encrypted = encrypt('Secret');
  const previous = process.env.DATA_ENCRYPTION_KEY;
  try {
    process.env.DATA_ENCRYPTION_KEY = 'cd'.repeat(32);
    assert.throws(() => decrypt(encrypted));
  } finally { process.env.DATA_ENCRYPTION_KEY = previous; }
});
test('Email lookup normalizes case and surrounding whitespace', () => {
  assert.equal(emailLookup(' USER@example.com '), emailLookup('user@example.com'));
});
test('Input validators reject nonstrings, control characters, and invalid IDs', () => {
  for (const input of [null, {}, [], 123, 'bad\u0000value']) {
    assert.throws(() => validate.text(input, 'Text'), { status: 400 });
  }
  for (const input of ['0', '-2', '2.5', 'invalid']) {
    assert.throws(() => validate.positiveInt(input), { status: 400 });
  }
  assert.equal(validate.email(' USER@example.com '), 'user@example.com');
});
test('Password policy requires length and all character classes', () => {
  for (const input of ['Ab1!', 'lowercaseonly123!', 'UPPERCASEONLY123!', 'NoNumbersHere!!', 'NoSymbolsHere123']) {
    assert.throws(() => validate.password(input), { status: 400 });
  }
  assert.equal(validate.password('StrongPassword123!'), 'StrongPassword123!');
});
