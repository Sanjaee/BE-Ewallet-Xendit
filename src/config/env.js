// File: src/config/env.js
require("dotenv").config();

module.exports = {
  // Database
  DATABASE_URL: process.env.DATABASE_URL,
  
  // Server
  PORT: process.env.PORT || 3000,
  NODE_ENV: process.env.NODE_ENV || 'development',
  
  // Redis Cache
  UPSTASH_REDIS_REST_URL: process.env.UPSTASH_REDIS_REST_URL,
  UPSTASH_REDIS_REST_TOKEN: process.env.UPSTASH_REDIS_REST_TOKEN,
  
  // Xendit Payment Gateway
  XENDIT_SECRET_KEY: process.env.XENDIT_SECRET_KEY,
  
  // Callback URLs
  NGROK_URL: process.env.NGROK_URL,
  PRODUCTION_URL: process.env.PRODUCTION_URL,
  SUCCESS_REDIRECT_URL: process.env.SUCCESS_REDIRECT_URL || "http://localhost:3001/success",
  FAILURE_REDIRECT_URL: process.env.FAILURE_REDIRECT_URL || "http://localhost:3001/failure",
  
  // Email Configuration
  EMAIL_SERVICE: process.env.EMAIL_SERVICE || 'gmail',
  EMAIL_USER: process.env.EMAIL_USER,
  EMAIL_PASSWORD: process.env.EMAIL_PASSWORD,
  EMAIL_FROM: process.env.EMAIL_FROM || process.env.EMAIL_USER,
};