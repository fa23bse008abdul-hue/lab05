const express = require('express');
const { authenticateJWT } = require('../middleware/auth');
const checkRole = require('../middleware/rbac');

const router = express.Router();

// All authenticated roles
router.get('/profile', authenticateJWT, checkRole(['SuperAdmin', 'Manager', 'Employee']), (req, res) => {
  res.json({
    message: 'Profile retrieved successfully',
    user: { id: req.user.id, email: req.user.email, role: req.user.role },
    timestamp: new Date(),
  });
});

module.exports = router;
