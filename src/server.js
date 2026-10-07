const mongoose = require('mongoose');
const cfg = require('./config/env');
const app = require('./app');
const { seedDemoUsers } = require('./utils/seed');

(async () => {
  try {
    await mongoose.connect(cfg.mongoUri);
    console.log('MongoDB connected');
    if (process.env.AUTO_SEED === 'true') {
      await seedDemoUsers();
      console.log('Demo users ensured');
    }
    app.listen(cfg.port, () => console.log(`Gateway running on port ${cfg.port}`));
  } catch (err) {
    console.error('Startup failure:', err.message);
    process.exit(1);
  }
})();
