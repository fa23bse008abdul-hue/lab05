const express = require('express');
const mongoose = require('mongoose');
const { authenticateJWT } = require('../middleware/auth');
const checkRole = require('../middleware/rbac');
const User = require('../models/User');
const RefreshToken = require('../models/RefreshToken');

const router = express.Router();

// SuperAdmin only
router.delete('/:id', authenticateJWT, checkRole(['SuperAdmin']), async (req, res, next) => {
  try {
    const { id } = req.params;
    if (!mongoose.isValidObjectId(id)) return res.status(400).json({ message: 'Invalid user id' });
    if (id === req.user.id) return res.status(400).json({ message: 'You cannot delete your own account' });

    const user = await User.findByIdAndDelete(id);
    if (!user) return res.status(404).json({ message: 'User not found' });

    await RefreshToken.deleteMany({ user: id }); // revoke every session of the deleted user
    res.json({ message: `User ${id} permanently deleted by SuperAdmin.` });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
