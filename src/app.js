const path = require('path');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const cfg = require('./config/env');
const passport = require('./config/passport');
const { sanitizeInput } = require('./middleware/sanitize');
const { apiLimiter } = require('./middleware/rateLimiter');

const app = express();

app.disable('x-powered-by');
app.set('trust proxy', 1); // Render/Railway/Vercel sit behind a proxy: needed for correct client IPs in rate limiting

// ----- OWASP hardening -----
app.use(helmet()); // CSP, HSTS, noSniff, frameguard, ...

// Strict CORS allow-list (no wildcard, credentials only for listed origins)
app.use(
  cors({
    origin(origin, cb) {
      if (!origin || cfg.corsOrigins.includes(origin)) return cb(null, true); // no Origin = Postman / same-origin
      cb(Object.assign(new Error('Origin not allowed by CORS policy'), { status: 403 }));
    },
    credentials: true,
    methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  })
);

app.use(express.json({ limit: '10kb' })); // body-size limit (DoS)
app.use(cookieParser());
app.use(sanitizeInput); // NoSQL injection + XSS
app.use(passport.initialize());

// ----- Routes -----
app.get('/health', (req, res) => res.json({ status: 'ok' }));
app.use('/api/', apiLimiter);
app.use('/api/v1/auth', require('./routes/auth'));
app.use('/api/v1/employee', require('./routes/employee'));
app.use('/api/v1/payroll', require('./routes/payroll'));
app.use('/api/v1/users', require('./routes/users'));

// Demo client (same origin => SameSite=Strict cookie works)
app.use(express.static(path.join(__dirname, '..', 'public')));

app.use('/api', (req, res) => res.status(404).json({ message: 'Route not found' }));

// Central error handler: never leak internals
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  const status = err.status || (err.type === 'entity.parse.failed' ? 400 : 500);
  if (status >= 500) console.error(err);
  res.status(status).json({ message: status >= 500 ? 'Internal server error' : err.message });
});

module.exports = app;
