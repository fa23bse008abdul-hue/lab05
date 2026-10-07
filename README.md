# Enterprise Multi-Tenant Security Gateway

CSC337 – Lab 05. Node.js / Express / MongoDB gateway with **hybrid authentication** (local Bcrypt + Google/GitHub OAuth 2.0), **JWT access + rotating refresh tokens**, **RBAC**, and **OWASP hardening**.

- **Live URL:** `https://<your-app>.onrender.com`  _(replace after deploying)_
- **Repo:** `https://github.com/<your-username>/enterprise-security-gateway`  _(must be PUBLIC)_

## Test credentials

| Role       | Email                       | Password               |
|------------|-----------------------------|------------------------|
| SuperAdmin | superadmin@enterprise.com   | `SuperPassword123!`    |
| Manager    | manager@enterprise.com      | `ManagerPassword123!`  |
| Employee   | employee@enterprise.com     | `EmployeePassword123!` |

Created by `npm run seed` (or automatically when `AUTO_SEED=true`). Passwords are stored only as bcrypt hashes.

## Features

| Requirement | Implementation |
|---|---|
| Local auth | `POST /api/v1/auth/register`, `POST /api/v1/auth/login` – bcrypt (12 rounds, per-password salt) |
| Lockout / rate limit | `express-rate-limit`: max **5 failed logins / 15 min / IP** (successes not counted) **plus** per-account lockout (423) for 15 min after 5 failures |
| OAuth 2.0 | Google + GitHub via Passport.js; profile synced to `User`; email linking only when provider marks email **verified**; new users are always `Employee` |
| Access token | JWT, **15 min**, sent as `Authorization: Bearer` |
| Refresh token | JWT, **7 days**, `httpOnly` + `Secure` (prod) + `SameSite=Strict` cookie, path-scoped to `/api/v1/auth`, stored in DB as **SHA-256 hash** |
| Rotation | `POST /api/v1/auth/refresh` revokes the used token and issues a new pair. **Reuse detection:** replaying an old token revokes the entire token family |
| Revocation | `POST /api/v1/auth/logout` revokes the family and clears the cookie |
| RBAC | `checkRole([...])` middleware (`SuperAdmin`, `Manager`, `Employee`) |
| OWASP | Helmet, strict CORS allow-list, body size limit, `express-mongo-sanitize` + `xss` sanitising body/query/params, input validation, generic error messages, no stack traces |

### Route access matrix

| Route | SuperAdmin | Manager | Employee |
|---|:-:|:-:|:-:|
| `GET /api/v1/employee/profile` | ✅ | ✅ | ✅ |
| `POST /api/v1/payroll/approve` | ✅ | ✅ | ❌ 403 |
| `DELETE /api/v1/users/:id` | ✅ | ❌ 403 | ❌ 403 |

Public `/register` **always** creates an `Employee` (role in the request body is ignored – prevents privilege escalation).

## Run locally

```bash
git clone <repo> && cd enterprise-security-gateway
npm install
cp .env.example .env        # fill MONGO_URI + two DIFFERENT JWT secrets
npm run seed
npm run dev                 # http://localhost:5000  (demo client at /)
```

Generate secrets:
```bash
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

## OAuth setup

- **Google** (console.cloud.google.com → APIs & Services → Credentials → OAuth client ID, Web)
  Authorized redirect URI: `https://<your-app>.onrender.com/api/v1/auth/google/callback`
- **GitHub** (Settings → Developer settings → OAuth Apps)
  Callback URL: `https://<your-app>.onrender.com/api/v1/auth/github/callback`
- For local testing use `http://localhost:5000/...` as a second redirect URI / separate OAuth app.

## Deploy on Render (recommended)

Render runs a long-lived Express server, which suits cookies, rate limiting and Mongo connections (Vercel's serverless model does not).

1. Create a free **MongoDB Atlas** cluster → Network Access: allow `0.0.0.0/0` → copy the connection string.
2. Push this repo to GitHub (**public**). `.env` is git-ignored; never commit it.
3. Render → **New Web Service** → connect repo. Build: `npm install`, Start: `npm start`.
4. Environment variables:

| Key | Value |
|---|---|
| `NODE_ENV` | `production` |
| `MONGO_URI` | Atlas string |
| `JWT_ACCESS_SECRET` / `JWT_REFRESH_SECRET` | two different random strings |
| `BASE_URL` | `https://<your-app>.onrender.com` |
| `CORS_ORIGINS` | `https://<your-app>.onrender.com` |
| `GOOGLE_CLIENT_ID/SECRET`, `GITHUB_CLIENT_ID/SECRET` | from provider consoles |
| `AUTO_SEED` | `true` (creates the 3 demo accounts on boot) |

5. Open the URL → demo client loads over HTTPS. Free-tier services sleep when idle; open the URL once before the viva.

## Viva cheat-sheet (Postman)

1. **Login** – `POST /api/v1/auth/login` `{ "email": "...", "password": "..." }` → copy `accessToken`; cookie `refreshToken` is set (HttpOnly).
2. **RBAC** – log in as Employee → `POST /payroll/approve` with Bearer token → **403**. As Manager → **200**. Manager `DELETE /users/:id` → **403**; SuperAdmin → **200**.
3. **Refresh rotation** – `POST /auth/refresh` twice using the *same old* cookie value → first 200 (new cookie), second **403** (reuse detected, family revoked).
4. **Rate limit / lockout** – 6 wrong passwords → 5×`401`, then `429`; the account itself then returns `423` even with the correct password.
5. **OAuth** – browser: click *Sign in with Google/GitHub* on the demo page → redirected back, session restored through the refresh cookie.
6. **Injection** – login with `{"email":{"$ne":null},"password":{"$ne":null}}` → rejected.

## Project structure

```
src/
  app.js            Express app (helmet, CORS, sanitising, routes)
  server.js         DB connect + listen
  config/           env validation, passport strategies
  middleware/       auth (JWT), rbac (checkRole), rateLimiter, sanitize
  models/           User, RefreshToken
  routes/           auth, employee, payroll, users
  utils/            tokens, seed
public/             demo client (index.html, app.js)
```

## Security notes / limitations

- Role is embedded in the 15-min access token, so a role change takes effect on next refresh.
- `SameSite=Strict` requires the client and API to share a site (the bundled demo client does).
- Rate limiting is in-memory per instance; use a shared store (e.g. Redis) when scaling horizontally.
