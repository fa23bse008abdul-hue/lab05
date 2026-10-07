const rateLimit = require('express-rate-limit');

const json429 = (message) => (req, res) => res.status(429).json({ message });

// Login: max 5 FAILED attempts per IP per 15 minutes (successful logins are not counted)
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  skipSuccessfulRequests: true,
  standardHeaders: true,
  legacyHeaders: false,
  handler: json429('Too many failed login attempts. Try again after 15 minutes.'),
});

// Registration / refresh: looser limit to stop abuse
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  handler: json429('Too many requests. Please slow down.'),
});

// Global safety net for the whole API
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  handler: json429('Too many requests from this IP.'),
});

module.exports = { loginLimiter, authLimiter, apiLimiter };
