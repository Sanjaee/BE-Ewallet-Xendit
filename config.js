// config.js
require('dotenv').config();

// Environment variables with defaults and validation
const config = {
  port: process.env.PORT || 3000,
  nodeEnv: process.env.NODE_ENV || 'development',
  
  // Database
  databaseUrl: process.env.DATABASE_URL,
  
  // Xendit
  xenditSecretKey: process.env.XENDIT_SECRET_KEY,
  xenditCallbackUrl: process.env.CALLBACK_URL || 'https://localhost:3000/callbacks/xendit',
  
  // Frontend URLs
  frontendUrl: process.env.FRONTEND_URL || 'http://localhost:3000',
  
  // Redirect URLs
  successRedirectUrl: process.env.SUCCESS_REDIRECT_URL || 'http://localhost:3000/wallet/success',
  failureRedirectUrl: process.env.FAILURE_REDIRECT_URL || 'http://localhost:3000/wallet/failure',
};

// Validate required config
const requiredConfigs = ['databaseUrl', 'xenditSecretKey'];
const missingConfigs = requiredConfigs.filter(configKey => !config[configKey]);

if (missingConfigs.length > 0) {
  throw new Error(`Missing required configuration: ${missingConfigs.join(', ')}`);
}

module.exports = config;