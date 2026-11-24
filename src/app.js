/**
 * src/app.js
 * Express application setup and HTTP/HTTPS server entrypoint.
 */

require('dotenv').config();

const fs = require('fs');
const http = require('http');
const https = require('https');
const express = require('express');
const helmet = require('helmet');
const session = require('express-session');

const authRoutes = require('./routes/auth');
const messageRoutes = require('./routes/messages');
const demoRoutes = require('./routes/demo');
const { errorHandler } = require('./middleware/errorHandler');

function validateEnv() {
  const required = ['SESSION_SECRET', 'DB_USER', 'DB_PASSWORD', 'DB_NAME'];
  const missing = required.filter((key) => !process.env[key]);
  if (missing.length > 0) {
    throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
  }
}

validateEnv();

const app = express();

// Disable X-Powered-By header and apply Helmet security headers
app.disable('x-powered-by');
app.use(helmet());

// Limit JSON request body size; CORS is intentionally disabled (no cors middleware)
app.use(express.json({ limit: '10kb' }));

// Session configuration: httpOnly, strict sameSite, 30-minute idle expiry
app.use(
  session({
    name: 'chatroom.sid',
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
      httpOnly: true,
      sameSite: 'strict',
      secure: process.env.NODE_ENV === 'production',
      maxAge: 30 * 60 * 1000, // 30 minutes idle timeout
    },
  })
);

// Core API routes
app.use('/api', authRoutes);
app.use('/api/messages', messageRoutes);

// Mount intentionally vulnerable demo route ONLY when DEMO_MODE=true and not production
if (process.env.DEMO_MODE === 'true' && process.env.NODE_ENV !== 'production') {
  app.use('/api/demo', demoRoutes);
}

// 404 fallback for unknown endpoints
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Central error handler (no stack traces or SQL details leaked)
app.use(errorHandler);

function startServer() {
  const port = Number(process.env.PORT) || 3000;
  // Bind to localhost by default (especially important when DEMO_MODE=true)
  const host = process.env.HOST || '127.0.0.1';

  let server;
  if (process.env.TLS_ENABLED === 'true') {
    const keyPath = process.env.TLS_KEY_PATH;
    const certPath = process.env.TLS_CERT_PATH;
    if (!keyPath || !certPath) {
      throw new Error('TLS_ENABLED=true requires TLS_KEY_PATH and TLS_CERT_PATH');
    }
    const tlsOptions = {
      key: fs.readFileSync(keyPath),
      cert: fs.readFileSync(certPath),
    };
    server = https.createServer(tlsOptions, app);
  } else {
    server = http.createServer(app);
  }

  server.listen(port, host, () => {
    const protocol = process.env.TLS_ENABLED === 'true' ? 'https' : 'http';
    console.log(`Chatroom API listening on ${protocol}://${host}:${port}`);
    if (process.env.DEMO_MODE === 'true' && process.env.NODE_ENV !== 'production') {
      console.warn(
        '[WARNING] DEMO_MODE is enabled: /api/demo/login-unsafe is active on localhost only.'
      );
    }
  });

  return server;
}

if (require.main === module) {
  startServer();
}

module.exports = { app, startServer };
