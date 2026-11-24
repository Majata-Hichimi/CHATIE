# Secure Chatroom Backend API (BIT3360 — Database Security)

## Purpose
This project is a **backend-only JSON REST API** built for **BIT3360 Advanced Databases** to demonstrate practical database and application security controls on `localhost` using sample data only.

It implements a minimal authenticated chatroom (register, login, logout, profile, and CRUD for messages) alongside:
- Least-privilege MySQL 8 roles (`chat_admin`, `chat_app`, `chat_readonly`)
- Parameterised queries and strict input validation
- An intentionally vulnerable route (`POST /api/demo/login-unsafe`, gated behind `DEMO_MODE=true` on localhost) for live SQL injection comparison
- Append-only security audit logging (`audit_log`)
- Four runnable demonstration scripts in `demo/` that output formatted tables for slides

---

## Prerequisites
- **Node.js** (LTS, v18+ recommended; Node v24 verified) and `npm`
- **MySQL 8.0+** running locally on `localhost:3306`
- `curl` or Postman for manual API testing (optional; `demo/` scripts automate all demonstrations)

---

## Setup and Run Instructions

### 1. Install dependencies
```bash
npm install
```

### 2. Configure environment variables
Copy `.env.example` to `.env` and replace all `CHANGE_ME_*` placeholders:
```bash
cp .env.example .env
```
In `.env`, set:
- `SESSION_SECRET`: a strong random secret (at least 32 characters; e.g., `openssl rand -hex 32`)
- `DB_PASSWORD`: password for the `chat_app` MySQL account
- `DB_ADMIN_PASSWORD`: password for `chat_admin` (used only by `seed.js`, `setup-db.js`, and `demo/`)
- `DB_READONLY_PASSWORD`: password for `chat_readonly` (used only by `demo/01-permissions.js`)
- `DEMO_MODE=true` when running the SQL injection demo locally (keep `false` otherwise)

> Never commit `.env` to version control. `.gitignore` excludes `.env` and `node_modules/`.

### 3. Initialize the MySQL schema and roles
Update the `CHANGE_ME_*` passwords in `roles.sql` (or let `npm run setup-db` substitute them in memory from `.env`), then apply `schema.sql` and `roles.sql` using a privileged MySQL administrator account:

If your MySQL `root` user uses `auth_socket` (default on Ubuntu):
```bash
sudo mysql < schema.sql
sudo mysql < roles.sql
```
If your admin/root account uses password authentication (or after `chat_admin` exists with `GRANT` privileges, or passing `DB_SETUP_USER=root DB_SETUP_PASSWORD=...`):
```bash
npm run setup-db
```

### 4. Seed sample data
Seeds sample users (`alice`, `bob`, `charlie`) and sample messages as `chat_admin`:
```bash
npm run seed
```
Sample demo credentials created by `seed.js`:
- `alice` / `AlicePassword1!`
- `bob` / `BobPassword1!`
- `charlie` / `CharliePassword1!`

### 5. Start the API server
```bash
npm start
```
The server binds to `127.0.0.1:3000` by default (connecting to MySQL strictly as `chat_app`).

### 6. Run the demonstration scripts
With the server running in another terminal (`DEMO_MODE=true` in `.env` for Demo 02):
```bash
npm run demo
```
Or run them individually:
```bash
node demo/01-permissions.js
node demo/02-sql-injection.js
node demo/03-audit-log.js
node demo/04-access-control.js
```

---

## API Endpoints

| Method | Endpoint | Auth Required | Description |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/register` | No | Register a new account (`username` + `password` only, no PII). Rate-limited. |
| `POST` | `/api/login` | No | Authenticate, regenerate session ID, enforce 5-attempt lockout. Rate-limited. |
| `POST` | `/api/logout` | Yes (`401` if not) | Destroy session, clear cookie, write `LOGOUT` audit entry. |
| `GET` | `/api/me` | Yes (`401` if not) | Return current user `id`, `username`, and `created_at` (never password hash). |
| `GET` | `/api/messages` | Yes (`401` if not) | List messages with `?limit` (max 50, default 20) and `?offset` (default 0). |
| `POST` | `/api/messages` | Yes (`401` if not) | Create a message (1–500 non-whitespace chars). Writes `MESSAGE_CREATE` audit entry. |
| `PUT` | `/api/messages/:id` | Yes (Owner only) | Edit own message (`403` + `ACCESS_DENIED` if not owner, `404` if missing). |
| `DELETE` | `/api/messages/:id` | Yes (Owner only) | Delete own message (`403` + `ACCESS_DENIED` if not owner, `404` if missing). |
| `POST` | `/api/demo/login-unsafe` | Localhost + `DEMO_MODE=true` only | **Intentionally vulnerable** SQL concatenation route for Demo 02 only. |

---

## Security Measures Mapping

| Security Measure | Where Implemented | How to Demonstrate | Threat Prevented |
| :--- | :--- | :--- | :--- |
| **Parameterised SQL & `multipleStatements: false`** | `src/db.js`, `src/routes/auth.js`, `src/routes/messages.js`, `src/audit.js` | Run `node demo/02-sql-injection.js` to compare `/api/demo/login-unsafe` vs `/api/login`. | **SQL injection** |
| **Input Validation & DB `CHECK` Constraints** | `src/middleware/validate.js`, `schema.sql` (`chk_*` constraints) | Send invalid username (`ab`), blank password, or >500-char message via `curl` -> HTTP `400`. | **SQL injection**, data corruption |
| **Least-Privilege MySQL Roles** | `roles.sql`, `src/db.js` (rejects non-`chat_app` user) | Run `node demo/01-permissions.js` to see `chat_app` blocked from `DELETE users`, `SELECT/UPDATE/DELETE audit_log`, `DROP/CREATE`. | **Privilege abuse** |
| **bcrypt Hashing (cost 12) + Constant-Time Dummy Compare** | `src/routes/auth.js` (`BCRYPT_COST = 12`, `DUMMY_HASH`) | Register a user and inspect `users.password_hash` as `chat_admin`; login with unknown username still executes `bcrypt.compare`. | **Weak passwords**, **information leakage** (user enumeration) |
| **Account Lockout (5 failures -> 15 min)** | `src/routes/auth.js` (`MAX_FAILED_ATTEMPTS = 5`, `LOCKOUT_MINUTES = 15`) | Send 5 wrong passwords to `POST /api/login`; 5th and subsequent requests return HTTP `423` and log `ACCOUNT_LOCKED`. | **Brute force** |
| **IP Rate Limiting (10 req / 15 min)** | `src/middleware/rateLimit.js`, `src/routes/auth.js` | Send >10 requests in 15 min to `/api/login` or `/api/register` -> HTTP `429`. | **Brute force** |
| **Hardened Sessions & Fixation Defense** | `src/app.js` (`httpOnly`, `sameSite: 'strict'`, `rolling: true`, 30m `maxAge`), `src/routes/auth.js` (`req.session.regenerate`) | Inspect `Set-Cookie` header before and after `POST /api/login` to observe session ID rotation and flags. | **Session hijacking / fixation** |
| **Dual-Layer Ownership Access Control** | `src/routes/messages.js` (`WHERE id = ? AND user_id = ?` + `403` check), `src/middleware/auth.js` | Run `node demo/04-access-control.js` (`bob` gets `403` on `alice`'s message; `alice` gets `200`). | **Unauthorized access** |
| **Append-Only Security Audit Log** | `src/audit.js`, `schema.sql` (`audit_log`), `roles.sql` (`INSERT` only for `chat_app`) | Run `node demo/03-audit-log.js` to view `LOGIN_FAILED`, `LOGIN_SUCCESS`, `MESSAGE_*`, `ACCESS_DENIED`, `LOGOUT`. | **Privilege abuse** (log tampering), non-repudiation gaps |
| **Security Headers, Body Limit & Error Masking** | `src/app.js` (`helmet()`, `app.disable('x-powered-by')`, `10kb` JSON limit, no CORS), `src/middleware/errorHandler.js` | Inspect HTTP response headers (`curl -I`) and send malformed JSON -> generic `400`/`500` without stack traces or SQL errors. | **Information leakage** |
| **Optional Transport Encryption (TLS / `DB_SSL`)** | `src/app.js` (`TLS_ENABLED`), `src/db.js` (`DB_SSL`) | Set `TLS_ENABLED=true` with cert/key paths or `DB_SSL=true` in `.env`. | **Information leakage** (eavesdropping in transit) |

---

## Encryption Status (What Is and Is Not Implemented)
- **Implemented:**
  - Password hashing at rest using `bcrypt` (cost factor 12, per-password random salt).
  - Optional TLS (HTTPS) for the Express API (`TLS_ENABLED=true`, `TLS_KEY_PATH`, `TLS_CERT_PATH`).
  - Optional TLS/SSL for the MySQL connection (`DB_SSL=true`, `DB_SSL_CA`, `DB_SSL_REJECT_UNAUTHORIZED`).
- **Not Implemented (documented honestly):**
  - **Encryption at rest** via MySQL InnoDB tablespace encryption (`ENCRYPTION='Y'`) is **not** enabled in `schema.sql`, because it requires configuring a MySQL keyring plugin (`component_keyring_file` or KMS) on the host MySQL server. It can be enabled at the MySQL server level without changing application SQL.
  - Message contents in `messages.content` are stored in plaintext in the database (encrypted only in transit if TLS/`DB_SSL` are enabled).

---

## Challenges and Limitations
1. **In-memory session and rate-limit stores:** `express-session` and `express-rate-limit` use Node's default in-memory stores. Restarting the server clears active sessions and rate-limit counters, and this design does not scale across multiple server processes without an external store (e.g., Redis).
2. **Cookie `secure` flag in local HTTP testing:** `cookie.secure` is tied to `NODE_ENV=production` so `curl` works over plain `http://127.0.0.1:3000` in development. In production, both `NODE_ENV=production` and HTTPS (`TLS_ENABLED=true` or a TLS reverse proxy) are required.
3. **Host-based MySQL account (`'user'@'localhost'`):** `roles.sql` restricts users to `'localhost'`, which assumes the API and MySQL run on the same machine. Remote database hosts would require explicit host entries and mandatory `DB_SSL=true` certificate verification.
4. **Demo rate-limit interaction:** Because `/api/login` is rate-limited to 10 requests per 15 minutes per IP, running the full `demo/` suite repeatedly back-to-back from `127.0.0.1` can trigger HTTP `429` until the 15-minute window resets (or the server is restarted).
5. **No CSRF tokens:** Because there is no HTML frontend and cookies use `sameSite: 'strict'` with JSON-only `Content-Type`, CSRF risk is mitigated for modern browsers, though adding CSRF tokens would be recommended if a browser UI were ever added.
