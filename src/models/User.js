const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const BCRYPT_ROUNDS = 12;

const userSchema = new mongoose.Schema(
  {
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, select: false }, // never returned by default; absent for OAuth-only users
    role: { type: String, enum: ['SuperAdmin', 'Manager', 'Employee'], default: 'Employee' },
    provider: { type: String, enum: ['local', 'google', 'github'], default: 'local' },
    googleId: { type: String, index: true, sparse: true },
    githubId: { type: String, index: true, sparse: true },
    // Account lockout
    failedLoginAttempts: { type: Number, default: 0 },
    lockUntil: Date,
  },
  { timestamps: true }
);

// Salted + hashed (bcrypt generates a unique salt per password)
userSchema.pre('save', async function (next) {
  if (!this.isModified('password') || !this.password) return next();
  this.password = await bcrypt.hash(this.password, BCRYPT_ROUNDS);
  next();
});

userSchema.methods.comparePassword = function (candidate) {
  if (!this.password) return Promise.resolve(false); // OAuth-only account
  return bcrypt.compare(candidate, this.password);
};

userSchema.methods.isLocked = function () {
  return !!(this.lockUntil && this.lockUntil > Date.now());
};

module.exports = mongoose.model('User', userSchema);
