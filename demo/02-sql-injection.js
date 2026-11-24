/**
 * demo/02-sql-injection.js
 * Sends SQL injection payloads to the intentionally vulnerable /api/demo/login-unsafe
 * route and the hardened /api/login route, printing a side-by-side comparison.
 */

require('dotenv').config();

const { printTable, ApiClient, getBaseUrl } = require('./_helpers');

async function main() {
  const baseUrl = getBaseUrl();
  const client = new ApiClient(baseUrl);

  const payloads = [
    { label: "Tautology bypass", username: "' OR '1'='1" },
    { label: "Comment truncation", username: "alice'-- " },
    { label: "UNION injection", username: "' UNION SELECT 1, 'attacker'-- " },
  ];

  const rows = [];

  for (const item of payloads) {
    // 1. Test intentionally vulnerable route (string concatenation)
    const unsafeRes = await client.request('POST', '/api/demo/login-unsafe', {
      username: item.username,
      password: 'wrong-password',
    });

    const unsafeOutcome =
      unsafeRes.status === 200 && unsafeRes.data.queryReturnedRows
        ? 'BYPASSED (rows returned!)'
        : `HTTP ${unsafeRes.status}`;

    // 2. Test production-safe /api/login route (input validation + parameterised query)
    const safeRes = await client.request('POST', '/api/login', {
      username: item.username,
      password: 'WrongPassword1!',
    });

    const safeOutcome =
      safeRes.status === 400 || safeRes.status === 401
        ? `BLOCKED (HTTP ${safeRes.status})`
        : `UNEXPECTED (HTTP ${safeRes.status})`;

    rows.push([
      item.label,
      item.username,
      unsafeOutcome,
      safeOutcome,
    ]);
  }

  printTable(
    'DEMO 02: SQL Injection — Unsafe Concatenation vs Parameterised /api/login',
    ['Attack Type', 'Payload', '/api/demo/login-unsafe', '/api/login (Safe)'],
    rows
  );
}

main().catch((err) => {
  console.error('Demo 02 failed:', err.message);
  process.exit(1);
});
