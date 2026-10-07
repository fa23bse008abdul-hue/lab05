const jwt = require('jsonwebtoken');
const { accessSecret } = require('../config/env');

const authenticateJWT = (req, res, next) => {
  const header = req.headers.authorization || '';
  if (!header.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Authentication token required' });
  }
  try {
    req.user = jwt.verify(header.slice(7), accessSecret, { algorithms: ['HS256'] });
    next();
  } catch (err) {
    const expired = err.name === 'TokenExpiredError';
    return res.status(401).json({
      message: expired ? 'Access token expired' : 'Invalid access token',
      code: expired ? 'TOKEN_EXPIRED' : 'TOKEN_INVALID',
    });
  }
};

module.exports = { authenticateJWT };
