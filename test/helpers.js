// Test-only dependencies: never load .env or connect to PostgreSQL.
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test-only-secret-never-use-in-production';
process.env.DATA_ENCRYPTION_KEY = 'ab'.repeat(32);
process.env.SESSION_DURATION_HOURS = '1';
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
const calls = [];
let queryHandler;
const pool = { query: async (...args) => {
  calls.push(args);
  if (!queryHandler) throw new Error('Unexpected database query in test');
  return queryHandler(...args);
} };
// Substitute dependencies BEFORE loading routers. Unexpected DB access fails closed.
require.cache[require.resolve('../src/db')] = { exports: { pool } };
require.cache[require.resolve('../src/logger')] = { exports: { logger: { error() {}, info() {} } } };
const security = require('../src/security');
function reset(handler) { calls.length = 0; queryHandler = handler; }
function session(role = 'author', id = 7, options = {}) {
  return jwt.sign({ id, role }, process.env.JWT_SECRET, { expiresIn: '1h', ...options });
}
function response() {
  return { statusCode: 200, cookies: {},
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; return this; },
    cookie(name, value, options) { this.cookies[name] = { value, options }; return this; },
    clearCookie(name, options) { this.cleared = { name, options }; return this; },
  };
}
async function invoke(router, method, path, options = {}) {
  const route = router.stack.find(layer => layer.route?.path === path && layer.route.methods[method]);
  assert.ok(route, `Route ${method} ${path} exists`);
  const req = { method: method.toUpperCase(), path, cookies: {}, body: {}, params: {}, query: {}, ...options };
  const res = response();
  // Execute real route middleware in order, including authentication/authorization.
  for (const layer of route.route.stack) {
    let advanced = false;
    let failure;
    await layer.handle(req, res, error => { advanced = true; failure = error; });
    if (failure) { security.errorHandler(failure, req, res, () => {}); break; }
    if (!advanced) break;
  }
  return res;
}
module.exports = { calls, reset, session, response, invoke, security };
