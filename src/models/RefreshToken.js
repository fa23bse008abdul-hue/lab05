const mongoose = require('mongoose');

const refreshTokenSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    tokenHash: { type: String, required: true, unique: true }, // SHA-256 of the JWT, never the raw token
    family: { type: String, required: true, index: true }, // all rotations of one login share a family
    expiresAt: { type: Date, required: true },
    isRevoked: { type: Boolean, default: false },
    replacedByHash: String,
  },
  { timestamps: true }
);

// MongoDB auto-deletes expired documents
refreshTokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model('RefreshToken', refreshTokenSchema);
