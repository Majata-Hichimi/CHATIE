/**
 * demo/_helpers.js
 * Shared table printer and lightweight HTTP cookie-jar client for demo scripts.
 */

function printTable(title, headers, rows) {
  console.log(`\n=== ${title} ===`);
  const widths = headers.map((h, i) =>
    Math.max(
      String(h).length,
      ...rows.map((row) => String(row[i] ?? '').length)
    )
  );

  const line = '+' + widths.map((w) => '-'.repeat(w + 2)).join('+') + '+';
  const formatRow = (cols) =>
    '| ' +
    cols.map((c, i) => String(c ?? '').padEnd(widths[i])).join(' | ') +
    ' |';

  console.log(line);
  console.log(formatRow(headers));
  console.log(line);
  for (const row of rows) {
    console.log(formatRow(row));
  }
  console.log(line);
}

class ApiClient {
  constructor(baseUrl) {
    this.baseUrl = baseUrl;
    this.cookie = '';
  }

  async request(method, path, body = undefined) {
    const headers = {};
    if (this.cookie) {
      headers.Cookie = this.cookie;
    }
    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
    }

    const res = await fetch(`${this.baseUrl}${path}`, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });

    const setCookie = res.headers.get('set-cookie');
    if (setCookie) {
      // Keep only the cookie name=value pair for subsequent requests
      this.cookie = setCookie.split(';')[0];
    }

    const data = await res.json().catch(() => ({}));
    return { status: res.status, data };
  }
}

function getBaseUrl() {
  const protocol = process.env.TLS_ENABLED === 'true' ? 'https' : 'http';
  const host = process.env.HOST || '127.0.0.1';
  const port = process.env.PORT || 3000;
  return `${protocol}://${host}:${port}`;
}

module.exports = { printTable, ApiClient, getBaseUrl };
