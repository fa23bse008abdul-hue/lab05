const mongoose = require('mongoose');
const User = require('../models/User');

const DEMO_USERS = [
  { email: 'superadmin@enterprise.com', password: 'SuperPassword123!', role: 'SuperAdmin' },
  { email: 'manager@enterprise.com', password: 'ManagerPassword123!', role: 'Manager' },
  { email: 'employee@enterprise.com', password: 'EmployeePassword123!', role: 'Employee' },
];

// Only touches the 3 demo accounts; passwords are hashed by the model's pre-save hook.
const seedDemoUsers = async ({ force = false } = {}) => {
  for (const u of DEMO_USERS) {
    const exists = await User.findOne({ email: u.email });
    if (exists && !force) continue;
    if (exists) await User.deleteOne({ _id: exists._id });
    await User.create({ ...u, provider: 'local' });
  }
};

module.exports = { seedDemoUsers, DEMO_USERS };

if (require.main === module) {
  const cfg = require('../config/env');
  mongoose
    .connect(cfg.mongoUri)
    .then(() => seedDemoUsers({ force: true }))
    .then(() => {
      console.log('Demo users seeded (passwords hashed).');
      return mongoose.disconnect();
    })
    .catch((e) => {
      console.error(e);
      process.exit(1);
    });
}
