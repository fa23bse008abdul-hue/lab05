const express = require('express');
const jwt = require('jsonwebtoken');
const passport = require('../config/passport');
const User = require('../models/User');
const RefreshToken = require('../models/RefreshToken');
const cfg = require('../config/env');
const {
  COOKIE_NAME,
  sha256,
  generateAccessToken,
  issueRefreshToken,
  sendRefreshCookie,
  clearRefreshCookie,
} = require('../utils/tokens');
const { loginLimiter, authLimiter } = require('../middleware/rateLimiter');

const router = express.Router();

const MAX_ATTEMPTS = 5;
const LOCK_MS = 15 * 60 * 1000;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const PASSWORD_RE = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,72}$/; // bcrypt ignores bytes after 72

// ---------- 1. Register ----------
router.post('/register', authLimiter, async (req, res, next) => {
  try {
    const { email, password } = req.body;
    if (typeof email !== 'string' || typeof password !== 'string' || !EMAIL_RE.test(email)) {
      return res.status(400).json({ message: 'A valid email and password are required' });
    }
    if (!PASSWORD_RE.test(password)) {
      return res.status(400).json({
        message: 'Password must be 8-72 chars and include upper-case, lower-case and a number',
      });
    }
    if (await User.findOne({ email: email.toLowerCase() })) {
      return res.status(409).json({ message: 'User already exists' });
    }
    // SECURITY: role is NEVER taken from the request. Public sign-ups are always Employee.
    // Higher roles are assigned only by a SuperAdmin / the seed script.
    const user = await User.create({ email, password, role: 'Employee', provider: 'local' });
    res.status(201).json({ message: 'User registered successfully', userId: user._id });
  } catch (err) {
    if (err.code === 11000) return res.status(409).json({ message: 'User already exists' });
    next(err);
  }
});

// ---------- 2. Login (rate limit + account lockout) ----------
router.post('/login', loginLimiter, async (req, res, next) => {
  try {
    const { email, password } = req.body;
    if (typeof email !== 'string' || typeof password !== 'string') {
      return res.status(400).json({ message: 'Email and password are required' });
    }
    const invalid = () => res.status(401).json({ message: 'Invalid credentials' });

    const user = await User.findOne({ email: email.toLowerCase() }).select('+password');
    if (!user) return invalid();

    if (user.isLocked()) {
      const mins = Math.ceil((user.lockUntil - Date.now()) / 60000);
      return res.status(423).json({ message: `Account locked after ${MAX_ATTEMPTS} failed attempts. Try again in ${mins} min.` });
    }

    // Lock window over -> start counting from zero again
    if (user.lockUntil && user.lockUntil <= Date.now()) {
      user.failedLoginAttempts = 0;
      user.lockUntil = undefined;
    }

    if (!(await user.comparePassword(password))) {
      user.failedLoginAttempts += 1;
      if (user.failedLoginAttempts >= MAX_ATTEMPTS) user.lockUntil = new Date(Date.now() + LOCK_MS);
      await user.save();
      return invalid();
    }

    user.failedLoginAttempts = 0;
    user.lockUntil = undefined;
    await user.save();

    const { token } = await issueRefreshToken(user);
    sendRefreshCookie(res, token);
    res.json({
      message: 'Login successful',
      accessToken: generateAccessToken(user),
      user: { id: user._id, email: user.email, role: user.role },
    });
  } catch (err) {
    next(err);
  }
});

// ---------- 3. Refresh token rotation ----------
router.post('/refresh', authLimiter, async (req, res, next) => {
  try {
    const oldToken = req.cookies[COOKIE_NAME];
    if (!oldToken) return res.status(401).json({ message: 'Refresh token cookie required' });

    let decoded;
    try {
      decoded = jwt.verify(oldToken, cfg.refreshSecret, { algorithms: ['HS256'] });
    } catch (e) {
      clearRefreshCookie(res);
      return res.status(401).json({ message: 'Invalid or expired refresh token' });
    }

    const oldHash = sha256(oldToken);

    // Atomically revoke: only one concurrent request can win
    const stored = await RefreshToken.findOneAndUpdate(
      { tokenHash: oldHash, isRevoked: false },
      { isRevoked: true },
      { new: true }
    );

    if (!stored) {
      // Token unknown or ALREADY USED -> possible theft. Kill the whole token family.
      const reused = await RefreshToken.findOne({ tokenHash: oldHash });
      if (reused) await RefreshToken.updateMany({ family: reused.family }, { isRevoked: true });
      clearRefreshCookie(res);
      return res.status(403).json({ message: 'Refresh token reuse detected or token revoked. Please log in again.' });
    }

    const user = await User.findById(decoded.id);
    if (!user) {
      clearRefreshCookie(res);
      return res.status(401).json({ message: 'User no longer exists' });
    }

    const { token: newToken } = await issueRefreshToken(user, stored.family);
    stored.replacedByHash = sha256(newToken);
    await stored.save();

    sendRefreshCookie(res, newToken);
    res.json({
      accessToken: generateAccessToken(user),
      user: { id: user._id, email: user.email, role: user.role },
    });
  } catch (err) {
    next(err);
  }
});

// ---------- 4. Logout (revocation) ----------
router.post('/logout', async (req, res, next) => {
  try {
    const token = req.cookies[COOKIE_NAME];
    if (token) {
      const rec = await RefreshToken.findOne({ tokenHash: sha256(token) });
      if (rec) await RefreshToken.updateMany({ family: rec.family }, { isRevoked: true });
    }
    clearRefreshCookie(res);
    res.json({ message: 'Logged out. Refresh token revoked.' });
  } catch (err) {
    next(err);
  }
});

// ---------- 5. OAuth 2.0 (Google / GitHub) ----------
const oauthDone = async (req, res, next) => {
  try {
    // Only the httpOnly refresh cookie is set; the SPA then calls /refresh to get its access token.
    // This keeps tokens out of URLs, history and logs.
    const { token } = await issueRefreshToken(req.user);
    sendRefreshCookie(res, token);
    res.redirect(cfg.oauthSuccessRedirect);
  } catch (err) {
    next(err);
  }
};

const oauthRoutes = (provider, scope) => {
  const configured = (req, res, next) =>
    passport._strategy(provider)
      ? next()
      : res.status(503).json({ message: `${provider} login is not configured on this server` });

  router.get(`/${provider}`, configured, passport.authenticate(provider, { scope, session: false }));
  router.get(
    `/${provider}/callback`,
    configured,
    passport.authenticate(provider, { session: false, failureRedirect: '/?error=oauth_failed' }),
    oauthDone
  );
};

oauthRoutes('google', ['profile', 'email']);
oauthRoutes('github', ['user:email']);

module.exports = router;
