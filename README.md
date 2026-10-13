# CSC337 Mini-Shop Security Lab

Node.js + Express + SQLite. One codebase, two modes:

| Command | Mode |
|---|---|
| `npm run start:vuln` | **Vulnerable** (attack this first) |
| `npm start` | **Fixed** (needs `.env`, copy from `.env.example`) |
| `npm run start:evil` | Evil/CORS demo pages on port 4000 |
| `npm test` | Automated tests (run against the fixed app) |

Everything binds to `127.0.0.1`. Run attacks only against your own localhost.

## Setup
    npm install
    cp .env.example .env     # then put your own random secrets in .env
    # Windows PowerShell: copy .env.example .env

Demo accounts: `ali@shop.test` (id 101, order 1), `sara@shop.test` (id 102, order 2), password `Passw0rd!123`. Admin: `admin@shop.test` / `Adm1nPass!123`.

## Notes per part
- **A** `CSP_MODE=report-only` in `.env` first, then `enforce`. The Console shows the violation when the inline `onerror` is blocked.
- **B** Open the evil page as `http://127.0.0.1:4000` (not `localhost:4000`). Browsers treat different ports on the same hostname as the *same site*, so SameSite would not apply and the demo would be misleading. Log in at `http://localhost:3000` first (in the browser, via the pay-form route after a POST /login, or by using a REST client that shares cookies).
- **C** SQLite has no NoSQL operators, so the `{"$ne":null}` payload is sent for the proof and rejected by type-checking plus `express-mongo-sanitize`. Use Mongoose if you want a true Mongo demo.
- **E** `GET /echo?amount=10&amount=1000` shows HPP (array vs last value).
- **F** `cors-demo.html` (port 4000) triggers the OPTIONS preflight. Gitleaks: use a separate throwaway repo.
