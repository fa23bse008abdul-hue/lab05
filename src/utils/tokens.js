const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const RefreshToken = require('../models/RefreshToken');
const { accessSecret, refreshSecret, isProd } = require('../config/env');

const REFRESH_DAYS = 7;
const COOKIE_NAME = 'refreshToken';

const sha256 = (value) => crypto.createHash('sha256').update(value).digest('hex');

const generateAccessToken = (user) =>
  jwt.sign({ id: String(user._id), role: user.role, email: user.email }, accessSecret, {
    expiresIn: '15m',
    algorithm: 'HS256',
  });

// `family` is reused across rotations so a replayed (stolen) token can kill the whole chain.
const issueRefreshToken = async (user, family = crypto.randomUUID()) => {
  const token = jwt.sign({ id: String(user._id), jti: crypto.randomUUID() }, refreshSecret, {
    expiresIn: `${REFRESH_DAYS}d`,
    algorithm: 'HS256',
  });
  await RefreshToken.create({
    user: user._id,
    tokenHash: sha256(token),
    family,
    expiresAt: new Date(Date.now() + REFRESH_DAYS * 24 * 60 * 60 * 1000),
  });
  return { token, family };
};

const cookieOptions = {
  httpOnly: true, // JS cannot read it (XSS)
  secure: isProd, // HTTPS only in production
  sameSite: 'strict', // CSRF protection
  path: '/api/v1/auth', // only sent to auth endpoints
};

const sendRefreshCookie = (res, token) =>
  res.cookie(COOKIE_NAME, token, { ...cookieOptions, maxAge: REFRESH_DAYS * 24 * 60 * 60 * 1000 });

const clearRefreshCookie = (res) => res.clearCookie(COOKIE_NAME, cookieOptions);

module.exports = {
  COOKIE_NAME,
  sha256,
  generateAccessToken,
  issueRefreshToken,
  sendRefreshCookie,
  clearRefreshCookie,
};
