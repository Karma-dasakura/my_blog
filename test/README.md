# Backend security tests

Run from the project directory with Node.js 20 or later:

```powershell
npm test
# Equivalent security command:
npm run test:security
# Run one file:
node --test test/api-security.test.js
```

No additional dependencies, running server, Supabase account, or `.env` are needed.
Tests use disposable test keys and replace the database module before importing
the real routers. No users, posts, or comments are created in a real database.
Unexpected database queries fail the tests. Logging is mocked to avoid writing
test failures to application logs.

## Files

| File | Coverage |
| --- | --- |
| `api-security.test.js` | Real route handlers and their authentication/authorization middleware; login, registration, logout, role escalation, SQL parameters, ownership, encrypted storage, invalid input, error disclosure |
| `security.test.js` | CSRF middleware, JWT signing and expiry, production cookie flags, AES-GCM tampering and wrong-key rejection, input and password validation |
| `helpers.js` | Mock request/response objects, test environment, database stub, route middleware runner |

## Scope and limitations

These are unit tests of backend handlers and middleware. The route runner invokes
the registered handler stack directly rather than opening an HTTP port. CSRF is
tested separately because it is mounted globally in `server.js`. Database stubs
assert ownership conditions and parameter binding; they do not execute SQL or
prove PostgreSQL permissions, constraints, or row-level policies.

Passing tests do not certify the application as secure. End-to-end HTTP tests
would additionally be needed for middleware mounting/order, Helmet headers,
request size limits, malformed JSON, production rate limits, browser cookie
behavior, and a separate disposable test database. Never point destructive tests
at your production database.

Add new scenarios using `reset(handler)` to specify expected database behavior,
then `invoke(router, method, registeredPath, requestOptions)`. Keep tests in each
file sequential because their database stub and environment are shared.
