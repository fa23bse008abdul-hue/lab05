const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const User = require('../models/User');
const cfg = require('./env');

/**
 * Find or create a local user for an OAuth identity.
 * - Matches first by provider id.
 * - Links to an existing account by email ONLY if the provider says the email is verified
 *   (prevents account takeover through an unverified email).
 * - New users always get the least-privileged role: Employee.
 */
const findOrCreateOAuthUser = async ({ provider, providerId, email, emailVerified }) => {
  const idField = `${provider}Id`;

  let user = await User.findOne({ [idField]: providerId });
  if (user) return user;

  if (email && emailVerified) {
    user = await User.findOne({ email });
    if (user) {
      user[idField] = providerId;
      await user.save();
      return user;
    }
  }

  return User.create({
    email: email || `${provider}-${providerId}@users.noreply.local`,
    [idField]: providerId,
    provider,
    role: 'Employee',
  });
};

if (cfg.google.clientID && cfg.google.clientSecret) {
  passport.use(
    new GoogleStrategy(
      {
        clientID: cfg.google.clientID,
        clientSecret: cfg.google.clientSecret,
        callbackURL: `${cfg.baseUrl}/api/v1/auth/google/callback`,
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          const e = profile.emails && profile.emails[0];
          const user = await findOrCreateOAuthUser({
            provider: 'google',
            providerId: profile.id,
            email: e && e.value,
            emailVerified: !!(e && (e.verified === true || e.verified === 'true')),
          });
          done(null, user);
        } catch (err) {
          done(err);
        }
      }
    )
  );
}

if (cfg.github.clientID && cfg.github.clientSecret) {
  passport.use(
    new GitHubStrategy(
      {
        clientID: cfg.github.clientID,
        clientSecret: cfg.github.clientSecret,
        callbackURL: `${cfg.baseUrl}/api/v1/auth/github/callback`,
        scope: ['user:email'],
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          const emails = profile.emails || [];
          const best = emails.find((x) => x.primary && x.verified) || emails.find((x) => x.verified);
          const user = await findOrCreateOAuthUser({
            provider: 'github',
            providerId: String(profile.id),
            email: best && best.value,
            emailVerified: !!best,
          });
          done(null, user);
        } catch (err) {
          done(err);
        }
      }
    )
  );
}

module.exports = passport;
