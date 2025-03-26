import User from "../models/User.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import crypto from "crypto";
import dotenv from "dotenv";

// Load environment variables
dotenv.config();

// ✅ In-memory OTP storage (Use Redis for production)
const otpStorage = new Map();

// ✅ Configure Nodemailer
const transporter = nodemailer.createTransport({
  service: "Gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// ✅ Generate a 6-digit OTP
const generateOTP = () => crypto.randomInt(100000, 999999).toString();

/** ✅ **Step 1: Send OTP to Email** */
export const sendOtpForRegistration = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ success: false, message: "Email is required" });
    }

    const otp = generateOTP();
    console.log(`✅ Generated OTP for ${email}: ${otp}`);

    // ✅ Store OTP with 10-minute expiry
    otpStorage.set(email, { otp, expiresAt: Date.now() + 10 * 60 * 1000 });

    // ✅ Send OTP Email
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Your OTP Code",
      text: `Your OTP code is ${otp}. It is valid for 10 minutes.`,
    };

    await transporter.sendMail(mailOptions);
    console.log("✅ OTP Sent Successfully");

    res.status(200).json({ success: true, message: "OTP sent successfully" });

  } catch (error) {
    console.error("❌ Error sending OTP:", error);
    res.status(500).json({ success: false, message: "Failed to send OTP" });
  }
};

/** ✅ **Step 2: Verify OTP** */
export const verifyOtp = async (req, res) => {
  try {
    const { email, otp } = req.body;
    
    console.log(`🔍 Verifying OTP for email: ${email}`);

    if (!email || !otp) {
      return res.status(400).json({ success: false, message: "Email and OTP are required" });
    }

    const storedOTP = otpStorage.get(email);

    if (!storedOTP) {
      return res.status(400).json({ success: false, message: "OTP expired or not found" });
    }

    // ✅ Check OTP expiration
    if (Date.now() > storedOTP.expiresAt) {
      otpStorage.delete(email);
      return res.status(400).json({ success: false, message: "OTP expired" });
    }

    // ✅ Verify OTP
    if (storedOTP.otp !== otp) {
      return res.status(400).json({ success: false, message: "Invalid OTP" });
    }

    console.log("✅ OTP Verified Successfully");

    // ✅ Mark OTP as verified (prevent duplicate use)
    otpStorage.set(email, { verified: true });

    res.status(200).json({ success: true, message: "OTP verified successfully" });

  } catch (error) {
    console.error("❌ OTP Verification Error:", error);
    res.status(500).json({ success: false, message: "Failed to verify OTP" });
  }
};

/** ✅ **Step 3: Register User (After OTP Verification)** */
export const register = async (req, res) => {
  try {
    const { username, email, password, role, photo } = req.body;

    // ✅ Ensure OTP was verified before registration
    const otpStatus = otpStorage.get(email);
    if (!otpStatus || !otpStatus.verified) {
      return res.status(400).json({ success: false, message: "OTP verification required" });
    }

    // ✅ Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ success: false, message: "User already registered" });
    }

    // ✅ Hash password
    const salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(password, salt);

    // ✅ Create and save user
    const newUser = new User({
      username,
      email,
      password: hash,
      role,
      photo,
    });

    await newUser.save();

    // ✅ Remove OTP after successful registration
    otpStorage.delete(email);

    res.status(200).json({ success: true, message: "Successfully registered" });

  } catch (error) {
    console.error("❌ Registration Error:", error);
    res.status(500).json({ success: false, message: "Failed to register. Try again." });
  }
};

/** ✅ **Step 4: Login User** */
export const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // ✅ Check if user exists
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    // ✅ Validate password
    const isPasswordCorrect = await bcrypt.compare(password, user.password);

    if (!isPasswordCorrect) {
      return res.status(401).json({ success: false, message: "Incorrect Email or Password" });
    }

    // ✅ Remove password from response
    const { password: hashedPassword, role, ...rest } = user._doc;

    // ✅ Generate JWT token
    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET_KEY,
      { expiresIn: "15d" }
    );

    res.status(200).json({
      success: true,
      token,
      data: { ...rest },
      role,
    });

  } catch (error) {
    console.error("❌ Login Error:", error);
    res.status(500).json({ success: false, message: "Failed to login" });
  }
};
