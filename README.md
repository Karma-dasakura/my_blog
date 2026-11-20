# ELE201 Secure MyBlog

A compact full-stack publishing platform built for the ELE201 Secure Coding rubric. Users can register, sign in, create/edit/delete their own posts, browse by category, and comment on public posts. Admin users may delete any post and access the protected user endpoint.

## What was intentionally kept out

The reference project included OTP email verification, image uploads, profile images, external email validation, CI configuration, a large asset bundle, and unused dependencies. They are not needed to demonstrate the ELE201 requirements, so this version keeps the attack surface small.

## Setup

1. Install Node.js 20+ and run `npm install`.
2. In Supabase SQL Editor, run [`sql/schema.sql`](sql/schema.sql).
3. Copy `.env.example` to `.env`, then enter your Supabase PostgreSQL connection string and two strong secrets. Keep `DB_SSL_REJECT_UNAUTHORIZED=false` for a Supabase pooler URL that reports a self-signed chain; TLS encryption remains enabled.
4. Generate an AES key: `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`.
5. Run `npm start`, then open `http://localhost:3000`.

To create or reset an admin from the secure server terminal, run `npm run create-admin -- "Admin Name" admin@example.com "StrongPassword"`. There is deliberately no public role-change endpoint.

## Security controls

- bcrypt cost 12 password hashes; encrypted email at rest with AES-256-GCM; SHA-256 lookup hash permits login without storing plaintext email.
- Parameterized PostgreSQL queries, strict server-side allowlisted validation, DOM `textContent` rendering, Helmet CSP, JSON body limits, CSRF tokens, and rate limiting.
- One-hour signed JWT in `HttpOnly`, `SameSite=Strict`, `Secure` (production) cookie; RBAC and ownership checks on protected actions.
- Structured Winston logs avoid passwords, tokens, email contents, SQL connection strings, and stack traces in client responses.
- HTTPS is enforced when `FORCE_HTTPS=true` behind a TLS proxy. Supabase connection uses verified TLS.

See [`docs/ELE201_DOCUMENTATION.md`](docs/ELE201_DOCUMENTATION.md) and [`docs/SECURITY_TESTING.md`](docs/SECURITY_TESTING.md) for the submission report and test evidence.
# my_blog
