const checkRole = (allowedRoles) => (req, res, next) => {
  if (!req.user || !allowedRoles.includes(req.user.role)) {
    return res.status(403).json({
      message: `Access Denied: role '${req.user ? req.user.role : 'Guest'}' is not authorized for this resource.`,
    });
  }
  next();
};

module.exports = checkRole;
