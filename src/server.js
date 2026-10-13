require('dotenv').config();
const { createApp } = require('./app');

const secure = process.env.SECURE !== 'false';
const app = createApp({
  secure,
  dbPath: process.env.DB_PATH || ':memory:',
  jwtSecret: process.env.JWT_SECRET,
  sessionSecret: process.env.SESSION_SECRET,
  allowedOrigins: (process.env.ALLOWED_ORIGINS || '').split(',').filter(Boolean),
  cspMode: process.env.CSP_MODE || 'enforce',
  cookieSecure: process.env.COOKIE_SECURE === 'true',
});
const port = process.env.PORT || 3000;
app.listen(port, '127.0.0.1', () => console.log(`Mini-shop (${secure ? 'FIXED' : 'VULNERABLE'}) on http://localhost:${port}`));
