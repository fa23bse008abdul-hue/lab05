const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss');

const SKIP_KEYS = new Set(['password']); // never alter passwords

const clean = (value, key) => {
  if (SKIP_KEYS.has(key)) return value;
  if (typeof value === 'string') return xss(value);
  if (Array.isArray(value)) return value.map((v) => clean(v));
  if (value && typeof value === 'object') {
    for (const k of Object.keys(value)) value[k] = clean(value[k], k);
  }
  return value;
};

// 1) strips $ and . operator keys (NoSQL injection)  2) escapes HTML/JS in strings (XSS)
const sanitizeInput = [
  mongoSanitize({ replaceWith: '_' }),
  (req, res, next) => {
    if (req.body) clean(req.body);
    if (req.query) clean(req.query);
    if (req.params) clean(req.params);
    next();
  },
];

module.exports = { sanitizeInput };
