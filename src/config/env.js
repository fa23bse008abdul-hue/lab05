require('dotenv').config();

const required = ['MONGO_URI', 'JWT_ACCESS_SECRET', 'JWT_REFRESH_SECRET'];
const missing = required.filter((k) => !process.env[k]);
if (missing.length) {
  console.error(`Missing required environment variables: ${missing.join(', ')}`);
  process.exit(1);
}
if (process.env.JWT_ACCESS_SECRET === process.env.JWT_REFRESH_SECRET) {
  console.error('JWT_ACCESS_SECRET and JWT_REFRESH_SECRET must be different.');
  process.exit(1);
}

const isProd = process.env.NODE_ENV === 'production';
const port = process.env.PORT || 5000;
const baseUrl = (process.env.BASE_URL || `http://localhost:${port}`).replace(/\/$/, '');

module.exports = {
  isProd,
  port,
  baseUrl,
  mongoUri: process.env.MONGO_URI,
  accessSecret: process.env.JWT_ACCESS_SECRET,
  refreshSecret: process.env.JWT_REFRESH_SECRET,
  corsOrigins: (process.env.CORS_ORIGINS || baseUrl).split(',').map((s) => s.trim()).filter(Boolean),
  oauthSuccessRedirect: process.env.OAUTH_SUCCESS_REDIRECT || '/',
  google: {
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  },
  github: {
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
  },
};
