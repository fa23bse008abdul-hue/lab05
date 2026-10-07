const express = require('express');
const { authenticateJWT } = require('../middleware/auth');
const checkRole = require('../middleware/rbac');

const router = express.Router();

// Manager + SuperAdmin only
router.post('/approve', authenticateJWT, checkRole(['SuperAdmin', 'Manager']), (req, res) => {
  res.json({
    message: 'Payroll approved successfully by authorized management.',
    approvedBy: req.user.email,
    role: req.user.role,
  });
});

module.exports = router;
