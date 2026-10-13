const express = require('express');
const session = require('express-session');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const hpp = require('hpp');
const mongoSanitize = require('express-mongo-sanitize');
const Joi = require('joi');
const path = require('path');
const { csrfSync } = require('csrf-sync');

const esc = (s) =>
  String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const registerSchema = Joi.object({
  email: Joi.string().email({ tlds: { allow: false } }).max(254).required(),
  password: Joi.string().min(8).max(64).required(),
  phone: Joi.string().pattern(/^03\d{9}$/).required().messages({ 'string.pattern.base': 'phone must be 11 digits starting with 03' }),
  cnic: Joi.string().pattern(/^\d{5}-\d{7}-\d$/).required().messages({ 'string.pattern.base': 'cnic must look like 12345-1234567-1' }),
}); // unknown keys are rejected by default
const loginSchema = Joi.object({
  email: Joi.string().max(254).required(),
  password: Joi.string().max(64).required(),
});
const reviewSchema = Joi.object({ productId: Joi.number().integer().required(), text: Joi.string().max(500).required() });

/**
 * secure=false -> intentionally vulnerable (lab only, localhost only!)
 * secure=true  -> fixed
 */
function createApp(opts = {}) {
  const secure = opts.secure !== false;
  if (secure && (!opts.jwtSecret || !opts.sessionSecret)) throw new Error('JWT_SECRET and SESSION_SECRET must be set');
  // VULN: hard-coded secrets
  const jwtSecret = secure ? opts.jwtSecret : 'secret123';
  const sessionSecret = secure ? opts.sessionSecret : 'keyboardcat';
  const allowed = opts.allowedOrigins || [];

  // ---------- database + seed ----------
  const db = new Database(opts.dbPath || ':memory:');
  db.exec(`
    CREATE TABLE users(id INTEGER PRIMARY KEY, email TEXT UNIQUE, password TEXT, phone TEXT, cnic TEXT, role TEXT DEFAULT 'user');
    CREATE TABLE products(id INTEGER PRIMARY KEY, name TEXT, price INTEGER);
    CREATE TABLE reviews(id INTEGER PRIMARY KEY AUTOINCREMENT, product_id INTEGER, text TEXT);
    CREATE TABLE orders(id INTEGER PRIMARY KEY, user_id INTEGER, item TEXT, amount INTEGER, paid INTEGER DEFAULT 0);
  `);
  const pw = (p) => (secure ? bcrypt.hashSync(p, 8) : p); // VULN: plaintext passwords
  const ins = db.prepare('INSERT INTO users(id,email,password,phone,cnic,role) VALUES(?,?,?,?,?,?)');
  ins.run(1, 'admin@shop.test', pw('Adm1nPass!123'), '03000000000', '11111-1111111-1', 'admin');
  ins.run(101, 'ali@shop.test', pw('Passw0rd!123'), '03001111111', '22222-2222222-2', 'user');
  ins.run(102, 'sara@shop.test', pw('Passw0rd!123'), '03002222222', '33333-3333333-3', 'user');
  ['Laptop', 'Phone', 'Headphones'].forEach((n, i) => db.prepare('INSERT INTO products VALUES(?,?,?)').run(i + 1, n, (i + 1) * 100));
  db.prepare('INSERT INTO orders(id,user_id,item,amount) VALUES(1,101,\'Laptop\',300)').run();
  db.prepare('INSERT INTO orders(id,user_id,item,amount) VALUES(2,102,\'Phone\',200)').run();

  const app = express();

  // ---------- global middleware ----------
  if (secure) {
    // Part A: CSP. Start with CSP_MODE=report-only, then enforce.
    app.use(helmet({
      contentSecurityPolicy: {
        useDefaults: true,
        reportOnly: opts.cspMode === 'report-only',
        directives: { defaultSrc: ["'self'"], scriptSrc: ["'self'"], objectSrc: ["'none'"], upgradeInsecureRequests: null },
      },
    }));
    // Part F: origin whitelist, no wildcard
    app.use(cors({ origin: (o, cb) => cb(null, !o || allowed.includes(o)), credentials: true }));
  } else {
    app.use(cors()); // VULN: wildcard CORS
  }
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  if (secure) {
    app.use(mongoSanitize()); // strips $-operators from body (NoSQL defense)
    app.use(hpp());           // Part E: HTTP Parameter Pollution
    app.use(rateLimit({ windowMs: 60_000, limit: 100, standardHeaders: true, legacyHeaders: false })); // 100/min/IP
  }
  app.use(session({
    name: 'sid',
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: secure
      ? { httpOnly: true, sameSite: 'strict', secure: !!opts.cookieSecure } // set COOKIE_SECURE=true behind HTTPS
      : { httpOnly: false, sameSite: false },                                // VULN: no flags
  }));

  app.use(express.static(path.join(__dirname, 'public'))); // test console at /

  const { csrfSynchronisedProtection, generateToken } = csrfSync({
    getTokenFromRequest: (req) => (req.body && req.body._csrf) || req.headers['x-csrf-token'],
  });

  // ---------- auth helpers ----------
  const auth = (req, res, next) => {
    const h = req.headers.authorization || '';
    const t = h.startsWith('Bearer ') ? h.slice(7) : null;
    if (!t) return res.status(401).json({ error: 'Login required' });
    try {
      // VULN: jwt.decode never checks the signature, so a tampered role is trusted
      req.user = secure ? jwt.verify(t, jwtSecret, { algorithms: ['HS256'] }) : jwt.decode(t);
      if (!req.user) throw new Error('bad token');
      next();
    } catch (e) {
      res.status(401).json({ error: 'Invalid or expired token' });
    }
  };
  const needSession = (req, res, next) =>
    req.session.user ? next() : res.status(401).json({ error: 'Login required' });

  // ---------- routes ----------
  app.post('/register', (req, res) => {
    try {
      let b = req.body;
      if (secure) {
        const { value, error } = registerSchema.validate(b, { abortEarly: false });
        if (error) return res.status(400).json({ error: error.details.map((d) => d.message) });
        b = { ...value, password: bcrypt.hashSync(value.password, 8), role: 'user' };
      }
      // VULN (insecure mode): no validation, and role comes straight from the body (mass assignment)
      const r = db.prepare('INSERT INTO users(email,password,phone,cnic,role) VALUES(?,?,?,?,?)')
        .run(b.email ?? null, b.password ?? null, b.phone ?? null, b.cnic ?? null, b.role || 'user');
      res.status(201).json({ id: r.lastInsertRowid });
    } catch (e) {
      res.status(e.code === 'SQLITE_CONSTRAINT_UNIQUE' ? 409 : 500).json({ error: secure ? 'Could not register' : e.message });
    }
  });

  const loginLimiter = secure
    ? rateLimit({ windowMs: 15 * 60_000, limit: 5, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many login attempts' } })
    : (req, res, next) => next();

  app.post('/login', loginLimiter, (req, res) => {
    const { email, password } = req.body || {};
    let user;
    if (secure) {
      // injection-shaped input (objects/arrays instead of strings) is simply a failed login
      if ([email, password].some((v) => v !== undefined && typeof v !== 'string')) return res.status(401).json({ error: 'Invalid credentials' });
      const { error } = loginSchema.validate(req.body);
      if (error) return res.status(400).json({ error: error.details[0].message });
      const u = db.prepare('SELECT * FROM users WHERE email = ?').get(email); // parameterized
      user = u && bcrypt.compareSync(password, u.password) ? u : null;
    } else {
      try { // VULN: string-concatenated query
        user = db.prepare(`SELECT * FROM users WHERE email='${email}' AND password='${password}'`).get();
      } catch (e) { return res.status(500).json({ error: e.message }); }
    }
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    req.session.user = { id: user.id, role: user.role };
    const token = jwt.sign({ sub: user.id, role: user.role }, jwtSecret, { expiresIn: secure ? '15m' : '30d' });
    res.json({ token });
  });

  app.get('/products', (req, res) => {
    const s = req.query.search ?? '';
    let rows;
    try {
      rows = secure
        ? db.prepare('SELECT * FROM products WHERE name LIKE ?').all(`%${String(s)}%`)
        : db.prepare(`SELECT * FROM products WHERE name LIKE '%${s}%'`).all(); // VULN (bonus: also injectable)
    } catch (e) { return res.status(500).send(e.message); }
    const list = rows.map((p) => `<li><a href="/products/${p.id}/reviews">${esc(p.name)}</a> - $${p.price}</li>`).join('');
    // VULN: reflected unencoded
    res.type('html').send(`<h1>Results for: ${secure ? esc(s) : s}</h1><ul>${list}</ul>`);
  });

  app.post('/reviews', (req, res) => {
    if (secure) {
      const { error } = reviewSchema.validate(req.body);
      if (error) return res.status(400).json({ error: error.details[0].message });
    }
    db.prepare('INSERT INTO reviews(product_id,text) VALUES(?,?)').run(Number(req.body.productId), String(req.body.text));
    res.status(201).json({ ok: true });
  });

  app.get('/products/:id/reviews', (req, res) => {
    const rows = db.prepare('SELECT text FROM reviews WHERE product_id = ?').all(Number(req.params.id));
    // VULN: stored review rendered unencoded
    const items = rows.map((r) => `<li>${secure ? esc(r.text) : r.text}</li>`).join('');
    res.type('html').send(`<h1>Reviews</h1><ul>${items}</ul>`);
  });

  app.get('/orders/:id', auth, (req, res) => {
    const o = db.prepare('SELECT * FROM orders WHERE id = ?').get(Number(req.params.id));
    if (!o) return res.status(404).json({ error: 'Not found' });
    // FIX (BOLA): owner comes from the verified token, never from URL/body
    if (secure && o.user_id !== Number(req.user.sub)) return res.status(403).json({ error: 'Forbidden' });
    res.json(o);
  });

  app.get('/csrf-token', needSession, (req, res) => res.json({ token: generateToken(req) }));

  app.get('/orders/:id/pay-form', needSession, (req, res) => {
    const tokenField = secure ? `<input type="hidden" name="_csrf" value="${esc(generateToken(req))}">` : '';
    res.type('html').send(`<h1>Pay order ${esc(req.params.id)}</h1>
      <form method="POST" action="/orders/${esc(req.params.id)}/pay">${tokenField}<button>Pay</button></form>`);
  });

  app.post('/orders/:id/pay', ...(secure ? [csrfSynchronisedProtection] : []), needSession, (req, res) => {
    const o = db.prepare('SELECT * FROM orders WHERE id = ?').get(Number(req.params.id));
    if (!o) return res.status(404).json({ error: 'Not found' });
    if (secure && o.user_id !== Number(req.session.user.id)) return res.status(403).json({ error: 'Forbidden' });
    db.prepare('UPDATE orders SET paid = 1 WHERE id = ?').run(o.id);
    res.json({ paid: true, order: o.id });
  });

  app.get('/echo', (req, res) => {
    const a = req.query.amount;
    res.json({ received: a, isArray: Array.isArray(a) });
  });

  app.get('/admin/users', auth, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admins only' });
    res.json(db.prepare('SELECT id,email,role FROM users').all());
  });

  // ---------- errors ----------
  app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
    const status = err.status || 500;
    res.status(status).json({ error: status === 403 ? 'Invalid CSRF token' : secure ? 'Server error' : err.stack });
  });

  return app;
}

module.exports = { createApp };
