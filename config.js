/**
 * config.js
 * Central configuration with fixed localhost defaults and optional environment overrides.
 *
 * NOTE: Fixed sample passwords are acceptable here ONLY because this is a local
 * university assignment demonstration using sample data (never use fixed defaults in production).
 */

module.exports = {
  host: process.env.HOST || '127.0.0.1',
  port: Number(process.env.PORT) || 3000,

  // Session cookie signing secret (override via SESSION_SECRET if desired)
  sessionSecret:
    process.env.SESSION_SECRET || 'bit3360-local-sample-session-secret-only',

  // Enable intentionally vulnerable SQLi demo route ONLY when DEMO_MODE=true
  demoMode: process.env.DEMO_MODE === 'true',

  db: {
    host: process.env.DB_HOST || '127.0.0.1',
    port: Number(process.env.DB_PORT) || 3306,
    database: process.env.DB_NAME || 'chatroom_db',

    // Running server connects ONLY as chat_app (least privilege)
    app: {
      user: process.env.DB_USER || 'chat_app',
      password: process.env.DB_PASSWORD || 'AppPass123!',
    },

    // Used ONLY by demo.js and `npm run check` (never by server API routes)
    admin: {
      user: process.env.DB_ADMIN_USER || 'chat_admin',
      password: process.env.DB_ADMIN_PASSWORD || 'AdminPass123!',
    },
    readonly: {
      user: process.env.DB_READONLY_USER || 'chat_readonly',
      password: process.env.DB_READONLY_PASSWORD || 'ReadOnlyPass123!',
    },
  },
};
