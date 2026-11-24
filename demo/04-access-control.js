/**
 * demo/04-access-control.js
 * Demonstrates application + SQL-level ownership access control:
 *  - Unauthenticated request gets 401
 *  - Bob gets 403 Forbidden when trying to edit Alice's message (#1)
 *  - Alice gets 200 OK when editing her own message (#1)
 *  - Non-existent message gets 404 Not Found
 */

require('dotenv').config();

const { printTable, ApiClient, getBaseUrl } = require('./_helpers');

async function main() {
  const baseUrl = getBaseUrl();
  const anon = new ApiClient(baseUrl);
  const bob = new ApiClient(baseUrl);
  const alice = new ApiClient(baseUrl);

  const results = [];

  // 1. Unauthenticated edit attempt -> 401
  const unauthRes = await anon.request('PUT', '/api/messages/1', {
    content: 'Unauthenticated edit attempt',
  });
  results.push([
    'Anonymous',
    'PUT /api/messages/1',
    `HTTP ${unauthRes.status}`,
    unauthRes.status === 401 ? 'PASS' : 'FAIL',
  ]);

  // 2. Bob logs in and tries to edit Alice's message (#1) -> 403
  const bobLogin = await bob.request('POST', '/api/login', {
    username: 'bob',
    password: 'BobPassword1!',
  });
  if (bobLogin.status !== 200) {
    throw new Error(`Bob login failed: HTTP ${bobLogin.status}`);
  }

  const bobEditRes = await bob.request('PUT', '/api/messages/1', {
    content: 'Bob attempting to overwrite Alice message',
  });
  results.push([
    'bob (non-owner)',
    'PUT /api/messages/1',
    `HTTP ${bobEditRes.status}`,
    bobEditRes.status === 403 ? 'PASS' : 'FAIL',
  ]);

  // 3. Alice logs in and edits her own message (#1) -> 200
  const aliceLogin = await alice.request('POST', '/api/login', {
    username: 'alice',
    password: 'AlicePassword1!',
  });
  if (aliceLogin.status !== 200) {
    throw new Error(`Alice login failed: HTTP ${aliceLogin.status}`);
  }

  const aliceEditRes = await alice.request('PUT', '/api/messages/1', {
    content: 'Hello everyone! Welcome to the BIT3360 security demo (verified by Alice).',
  });
  results.push([
    'alice (owner)',
    'PUT /api/messages/1',
    `HTTP ${aliceEditRes.status}`,
    aliceEditRes.status === 200 ? 'PASS' : 'FAIL',
  ]);

  // 4. Non-existent message -> 404
  const notFoundRes = await alice.request('PUT', '/api/messages/99999', {
    content: 'Editing nonexistent message',
  });
  results.push([
    'alice',
    'PUT /api/messages/99999',
    `HTTP ${notFoundRes.status}`,
    notFoundRes.status === 404 ? 'PASS' : 'FAIL',
  ]);

  // Cleanly log out both sessions
  await bob.request('POST', '/api/logout');
  await alice.request('POST', '/api/logout');

  printTable(
    'DEMO 04: Ownership Access Control (401 / 403 / 200 / 404)',
    ['Actor', 'Request', 'Response', 'Status'],
    results
  );
}

main().catch((err) => {
  console.error('Demo 04 failed:', err.message);
  process.exit(1);
});
