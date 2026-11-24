# Secure Chatroom Backend API (BIT3360 — Database Security)

A simplified, localhost-only **JSON REST API** built with Node.js, Express, `mysql2`, `express-session`, and `bcryptjs` to demonstrate database security principles for **BIT3360 Advanced Databases**.

---

## Quick Start (4 Steps)

**Prerequisites:** Node.js 18+ and MySQL 8.0+ installed and running on `localhost`.

1. **Initialize the database, least-privilege roles, and sample data:**
   ```bash
   sudo mysql < setup.sql
   ```
   *(Or if your MySQL `root` user uses a password: `mysql -u root -p < setup.sql`)*

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Start the API server:**
   ```bash
   npm start
   ```
   Verify your setup anytime with:
   ```bash
   npm run check
   ```

4. **Run the full security demonstration (in a second terminal):**
   ```bash
   npm run demo
   ```

> **Note on fixed sample passwords:** [config.js](file:///home/majata/Desktop/CHATIE/config.js) and [setup.sql](file:///home/majata/Desktop/CHATIE/setup.sql) use fixed sample passwords so the project runs immediately with zero `.env` configuration. Fixed passwords are acceptable **only** because this is a local university assignment using sample data (never use fixed passwords in production). All values can still be overridden via environment variables.

---

## Sample Accounts

| Username | Password | Role |
| :--- | :--- | :--- |
| `alice` | `AlicePass123!` | Sample user (owns messages `#1`, `#4`) |
| `bob` | `BobPass123!` | Sample user (owns message `#2`) |
| `charlie` | `CharliePass123!` | Sample user (owns message `#3`) |

---

## API Endpoints & `curl` Examples

| Method | Endpoint | Auth | Purpose |
| :--- | :--- | :--- | :--- |
| `GET` | `/` | Public | Health check (`{"status":"ok",...}`) |
| `POST` | `/api/register` | Public | Register with `username` + `password` only |
| `POST` | `/api/login` | Public | Login, regenerate session, enforce lockout |
| `POST` | `/api/logout` | Required (`401`) | Destroy session & clear cookie |
| `GET` | `/api/me` | Required (`401`) | Current user (`id`, `username`, `created_at`) |
| `GET` | `/api/messages` | Required (`401`) | List messages (`?limit=20&offset=0`, max 50) |
| `POST` | `/api/messages` | Required (`401`) | Post a new message (1–500 non-empty chars) |
| `PUT` | `/api/messages/:id` | Owner (`403`/`404`) | Edit own message |
| `DELETE` | `/api/messages/:id` | Owner (`403`/`404`) | Delete own message |
| `POST` | `/api/demo/login-unsafe` | Localhost + `DEMO_MODE` | Intentionally vulnerable SQLi demo route |

### `curl` Examples
```bash
# Check server
curl http://127.0.0.1:3000/

# Register a new user
curl -X POST http://127.0.0.1:3000/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"diana_99","password":"DianaPass123!"}'

# Login and save session cookie
curl -c cookies.txt -X POST http://127.0.0.1:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"AlicePass123!"}'

# View current user and list messages
curl -b cookies.txt http://127.0.0.1:3000/api/me
curl -b cookies.txt "http://127.0.0.1:3000/api/messages?limit=10&offset=0"

# Create, edit, and delete a message
curl -b cookies.txt -X POST http://127.0.0.1:3000/api/messages \
  -H "Content-Type: application/json" \
  -d '{"content":"Testing secure chat API"}'

curl -b cookies.txt -X PUT http://127.0.0.1:3000/api/messages/1 \
  -H "Content-Type: application/json" \
  -d '{"content":"Edited by Alice"}'

curl -b cookies.txt -X DELETE http://127.0.0.1:3000/api/messages/5

# Logout
curl -b cookies.txt -X POST http://127.0.0.1:3000/api/logout
```

---

## Security Measures Mapping

| Security Measure | Where Implemented | Threat Prevented |
| :--- | :--- | :--- |
| **Parameterised queries (`?` placeholders) & `multipleStatements: false`** | [db.js](file:///home/majata/Desktop/CHATIE/db.js), [server.js](file:///home/majata/Desktop/CHATIE/server.js) | **SQL injection** |
| **Least-privilege MySQL roles (`chat_admin`, `chat_app`, `chat_readonly`)** | [setup.sql](file:///home/majata/Desktop/CHATIE/setup.sql), [db.js](file:///home/majata/Desktop/CHATIE/db.js) | **Privilege abuse** |
| **`bcryptjs` password hashing (cost 10) + constant-time dummy compare** | [server.js](file:///home/majata/Desktop/CHATIE/server.js) (`DUMMY_HASH`, `/api/register`, `/api/login`) | **Weak passwords**, **username enumeration** |
| **Account lockout (5 failed logins -> 15 min lock in DB)** | [server.js](file:///home/majata/Desktop/CHATIE/server.js), [setup.sql](file:///home/majata/Desktop/CHATIE/setup.sql) (`failed_attempts`, `locked_until`) | **Brute force** |
| **Hardened sessions (`httpOnly`, `sameSite: 'strict'`, 30m expiry, `regenerate`)** | [server.js](file:///home/majata/Desktop/CHATIE/server.js) | **Session hijacking & fixation** |
| **Input validation + DB `CHECK`/`UNIQUE`/`FK` constraints** | [server.js](file:///home/majata/Desktop/CHATIE/server.js), [setup.sql](file:///home/majata/Desktop/CHATIE/setup.sql) | **SQL injection**, invalid/corrupt data |
| **Central error handler & disabled `X-Powered-By`** | [server.js](file:///home/majata/Desktop/CHATIE/server.js) | **Information leakage** |
| **SQL-level ownership check (`WHERE id = ? AND user_id = ?`)** | [server.js](file:///home/majata/Desktop/CHATIE/server.js) (`PUT`/`DELETE /api/messages/:id`) | **Unauthorized access** (IDOR) |
| **Append-only `audit_log` (`chat_app` has `INSERT` only)** | [setup.sql](file:///home/majata/Desktop/CHATIE/setup.sql), [server.js](file:///home/majata/Desktop/CHATIE/server.js) (`writeAuditLog`) | **Privilege abuse** (log tampering), missing audit trail |

---

## Troubleshooting

- **MySQL not running:** Start the MySQL service (`sudo service mysql start` on Ubuntu/WSL, or check Services on Windows) and re-run `npm run check`.
- **Access denied (`ER_ACCESS_DENIED_ERROR`):** Re-run `sudo mysql < setup.sql` (or `mysql -u root -p < setup.sql`) so `chat_admin`, `chat_app`, and `chat_readonly` exist for both `'localhost'` and `'127.0.0.1'` with the passwords in `config.js`.
- **`setup.sql` not applied (`ER_BAD_DB_ERROR` / missing tables):** Run `sudo mysql < setup.sql` and verify with `npm run check`.
- **Port 3000 already in use (`EADDRINUSE`):** Stop the other server using port 3000, or start with `PORT=3001 npm start`. (`npm run demo` uses an ephemeral port automatically so it works even while `npm start` is running.)
- **MySQL too old:** Upgrade to MySQL 8.0+ (required for `CHECK` constraints and `utf8mb4_unicode_ci` behavior).

---

## Challenges and Limitations
1. **Local sample credentials:** `config.js` and `setup.sql` contain fixed sample passwords for ease of setup; a real deployment would load secrets from a secret manager or environment variables and enforce TLS/HTTPS.
2. **In-memory session store:** `express-session` stores sessions in Node.js memory, so restarting `server.js` logs active users out and does not share sessions across multiple instances.
3. **No encryption at rest or TLS in the simplified build:** Passwords are protected via `bcryptjs`, but message contents and network traffic on `127.0.0.1` are plaintext unless MySQL tablespace encryption and a TLS reverse proxy are configured.
4. **Account lockout without IP rate limiting:** To keep dependencies minimal (`express`, `express-session`, `mysql2`, `bcryptjs`), brute-force protection relies on the database-backed 5-attempt lockout rather than per-IP rate limiting.
