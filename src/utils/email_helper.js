// src/utils/email_helper.js
const nodemailer = require("nodemailer");
const dotenv = require("dotenv");
dotenv.config();
const {
  EMAIL_SERVICE,
  EMAIL_USER,
  EMAIL_PASSWORD,
  EMAIL_FROM,
} = require("../config/env");


const transporter = nodemailer.createTransport({
  service: EMAIL_SERVICE,
  auth: {
    user: EMAIL_USER,
    pass: EMAIL_PASSWORD,
  },
});

const sendOTPEmail = async (email, otp, type) => {
  let subject = "";
  let text = "";

  switch (type) {
    case "VERIFICATION":
      subject = "Account Verification OTP";
      text = `Your verification OTP is: ${otp}. It is valid for 5 minutes.`;
      break;
    case "PASSWORD_RESET":
      subject = "Password Reset OTP";
      text = `Your password reset OTP is: ${otp}. It is valid for 5 minutes.`;
      break;
    case "LOGIN":
      subject = "Login OTP";
      text = `Your login OTP is: ${otp}. It is valid for 5 minutes.`;
      break;
    default:
      subject = "OTP Code";
      text = `Your OTP is: ${otp}. It is valid for 5 minutes.`;
  }

  await transporter.sendMail({
    from: EMAIL_FROM,
    to: email,
    subject,
    text,
  });
};

module.exports = {
  sendOTPEmail,
};