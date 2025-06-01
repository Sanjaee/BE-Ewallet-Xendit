require("dotenv").config();
const { eWallet } = require("../config/xendit");
const { redis } = require("../config/redis");
const { sendOTPEmail } = require("../utils/email_helper");

const testXenditConnection = async () => {
  try {
    // Test EWallet connection by getting available payment methods
    const paymentMethods = await eWallet.getPaymentMethods();
    console.log("✅ Xendit EWallet connection successful");
    return true;
  } catch (error) {
    console.error("❌ Xendit connection test failed:", error.message);
    return false;
  }
};

const testRedisConnection = async () => {
  try {
    await redis.ping();
    console.log("✅ Redis connection successful");
    return true;
  } catch (error) {
    console.error("❌ Redis connection test failed:", error.message);
    return false;
  }
};

const testEmailConnection = async () => {
  try {
    await sendOTPEmail("test@example.com", "123456");
    console.log("✅ Email connection successful");
    return true;
  } catch (error) {
    console.error("❌ Email connection test failed:", error.message);
    return false;
  }
};

const testConnections = async () => {
  const [xenditSuccess, redisSuccess, emailSuccess] = await Promise.all([
    testXenditConnection(),
    testRedisConnection(),
    testEmailConnection(),
  ]);

  return [xenditSuccess, redisSuccess, emailSuccess];
};

module.exports = {
  testConnections,
  testXenditConnection,
  testRedisConnection,
  testEmailConnection,
};
