const { test, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const bcrypt = require('bcrypt');
const { calls, reset, session, invoke } = require('./helpers');
const auth = require('../src/routes/auth');
const posts = require('../src/routes/posts');
const { decrypt, emailLookup } = require('../src/crypto');
const password = 'StrongPassword123!';
const body = { title: 'A safe title', content: 'A sufficiently long story.' };
beforeEach(() => reset());

for (const [router, method, path] of [
  [auth, 'get', '/me'], [auth, 'delete', '/admin/users/:id'],
  [posts, 'get', '/mine'], [posts, 'get', '/admin/users'],
  [posts, 'post', '/'], [posts, 'put', '/:id'], [posts, 'delete', '/:id'],
  [posts, 'post', '/:id/comments'], [posts, 'delete', '/:id/comments/:commentId'],
]) test(`Unauthenticated ${method.toUpperCase()} ${router === auth ? '/auth' : '/posts'}${path} is rejected`, async () => {
  const res = await invoke(router, method, path);
  assert.equal(res.statusCode, 401);
  assert.equal(calls.length, 0);
});

test('Forged admin JWT cannot access admin API', async () => {
  const token = require('jsonwebtoken').sign({ id: 7, role: 'admin' }, 'wrong-secret');
  assert.equal((await invoke(posts, 'get', '/admin/users', { cookies: { session: token } })).statusCode, 401);
  assert.equal(calls.length, 0);
});
test('Expired session is rejected', async () => {
  assert.equal((await invoke(auth, 'get', '/me', { cookies: { session: session('author', 7, { expiresIn: -1 }) } })).statusCode, 401);
  assert.equal(calls.length, 0);
});
test('Author cannot list or delete users', async () => {
  const cookies = { session: session() };
  assert.equal((await invoke(posts, 'get', '/admin/users', { cookies })).statusCode, 403);
  assert.equal((await invoke(auth, 'delete', '/admin/users/:id', { cookies, params: { id: '8' } })).statusCode, 403);
  assert.equal(calls.length, 0);
});
test('Admin cannot delete their own account', async () => {
  const res = await invoke(auth, 'delete', '/admin/users/:id', { cookies: { session: session('admin') }, params: { id: '7' } });
  assert.equal(res.statusCode, 400);
  assert.equal(calls.length, 0);
});
test('Unknown email and wrong password return identical login errors', async () => {
  reset(() => ({ rows: [] }));
  const unknown = await invoke(auth, 'post', '/login', { body: { email: 'unknown@example.com', password } });
  reset(() => ({ rows: [{ id: 7, role: 'author', password_hash: bcrypt.hashSync(password, 4) }] }));
  const wrong = await invoke(auth, 'post', '/login', { body: { email: 'known@example.com', password: 'incorrect' } });
  assert.equal(unknown.statusCode, 401);
  assert.equal(wrong.statusCode, 401);
  assert.deepEqual(unknown.body, wrong.body);
  assert.deepEqual(wrong.cookies, {});
});
test('Valid login sets HttpOnly session and never returns password hash', async () => {
  reset(() => ({ rows: [{ id: 7, display_name: 'Tester', role: 'author', password_hash: bcrypt.hashSync(password, 4) }] }));
  const res = await invoke(auth, 'post', '/login', { body: { email: 'USER@example.com', password } });
  assert.equal(res.statusCode, 200);
  assert.deepEqual(res.body.user, { id: 7, name: 'Tester', role: 'author' });
  assert.equal(res.cookies.session.options.httpOnly, true);
  assert.equal(res.cookies.session.options.sameSite, 'lax');
  assert.deepEqual(calls[0][1], [emailLookup('user@example.com')]);
});
test('Malformed login input is rejected before querying database', async () => {
  for (const input of [{ email: 'not-email', password }, { email: {}, password }, { email: 'user@example.com', password: '' }]) {
    assert.equal((await invoke(auth, 'post', '/login', { body: input })).statusCode, 400);
  }
  assert.equal(calls.length, 0);
});
test('Weak registration password is rejected', async () => {
  assert.equal((await invoke(auth, 'post', '/register', { body: { name: 'Tester', email: 'user@example.com', password: 'weak' } })).statusCode, 400);
  assert.equal(calls.length, 0);
});
test('Registration hashes password, encrypts email and ignores requested admin role', async () => {
  reset(() => ({ rows: [{ id: 9, role: 'author' }] }));
  const res = await invoke(auth, 'post', '/register', { body: { name: 'Tester', email: 'user@example.com', password, role: 'admin' } });
  assert.equal(res.statusCode, 201);
  const [sql, values] = calls[0];
  assert.doesNotMatch(sql, /\brole\b(?=[^)]*\))/);
  assert.equal(res.body.user.role, 'author');
  assert.equal(values[1], emailLookup('user@example.com'));
  assert.equal(decrypt(values[2]), 'user@example.com');
  assert.equal(await bcrypt.compare(password, values[3]), true);
  assert.notEqual(values[3], password);
});
test('Category SQL injection payload is passed as a parameter', async () => {
  const payload = "x'; DROP TABLE users; --";
  reset(() => ({ rows: [] }));
  assert.equal((await invoke(posts, 'get', '/', { query: { category: payload } })).statusCode, 200);
  assert.ok(!calls[0][0].includes(payload));
  assert.deepEqual(calls[0][1], [payload]);
});
test('Invalid post ID is rejected before database access', async () => {
  for (const id of ['1 OR 1=1', '-1', '0', '1.5']) {
    assert.equal((await invoke(posts, 'get', '/:id', { params: { id } })).statusCode, 400);
  }
  assert.equal(calls.length, 0);
});
test('Post creation uses session author, encrypts content and rejects mass assignment', async () => {
  reset(() => ({ rows: [{ id: 12 }] }));
  const res = await invoke(posts, 'post', '/', { cookies: { session: session() }, body: { ...body, author_id: 999, role: 'admin' } });
  assert.equal(res.statusCode, 201);
  assert.equal(calls[0][1][0], 7);
  assert.equal(decrypt(calls[0][1][3]), body.content);
});
test('Oversized post is rejected without database access', async () => {
  const res = await invoke(posts, 'post', '/', { cookies: { session: session() }, body: { ...body, content: 'x'.repeat(10001) } });
  assert.equal(res.statusCode, 400);
  assert.equal(calls.length, 0);
});
test('Updating another author post enforces ownership in SQL', async () => {
  reset((sql, values) => {
    assert.match(sql, /WHERE id=\$3 AND author_id=\$4/);
    assert.deepEqual(values.slice(2), [12, 7]);
    return { rows: [] };
  });
  assert.equal((await invoke(posts, 'put', '/:id', { cookies: { session: session() }, params: { id: '12' }, body })).statusCode, 404);
  assert.equal(calls.length, 1);
});
test('Deleting another author post enforces ownership in SQL', async () => {
  reset((sql, values) => {
    assert.match(sql, /WHERE id=\$1 AND author_id=\$2/);
    assert.deepEqual(values, [12, 7]);
    return { rows: [] };
  });
  assert.equal((await invoke(posts, 'delete', '/:id', { cookies: { session: session() }, params: { id: '12' } })).statusCode, 404);
});
test('Admin may delete posts belonging to another author', async () => {
  reset((sql, values) => {
    assert.match(sql, /DELETE FROM posts WHERE id=\$1 RETURNING id/);
    assert.deepEqual(values, [12]);
    return { rows: [{ id: 12 }] };
  });
  assert.equal((await invoke(posts, 'delete', '/:id', { cookies: { session: session('admin') }, params: { id: '12' } })).statusCode, 200);
});
test('Comment deletion is limited to the session author', async () => {
  reset((sql, values) => {
    assert.match(sql, /WHERE id=\$1 AND author_id=\$2/);
    assert.deepEqual(values, [19, 7]);
    return { rows: [] };
  });
  assert.equal((await invoke(posts, 'delete', '/:id/comments/:commentId', { cookies: { session: session() }, params: { id: '12', commentId: '19' } })).statusCode, 404);
});
test('Comments are encrypted and require a published post', async () => {
  reset((sql, values) => {
    assert.match(sql, /published=TRUE/);
    assert.deepEqual(values.slice(0, 2), [12, 7]);
    assert.equal(decrypt(values[2]), 'Test comment');
    return { rows: [] };
  });
  assert.equal((await invoke(posts, 'post', '/:id/comments', { cookies: { session: session() }, params: { id: '12' }, body: { body: 'Test comment' } })).statusCode, 404);
});
test('Internal database errors are hidden from API response', async () => {
  reset(() => { throw new Error('private-password SQL SELECT users'); });
  const res = await invoke(auth, 'post', '/login', { body: { email: 'user@example.com', password } });
  assert.equal(res.statusCode, 500);
  assert.doesNotMatch(JSON.stringify(res.body), /private-password|SELECT|stack/);
});
test('Logout clears the session cookie', async () => {
  const res = await invoke(auth, 'post', '/logout');
  assert.equal(res.statusCode, 200);
  assert.equal(res.cleared.name, 'session');
  assert.equal(res.cleared.options.path, '/');
});
