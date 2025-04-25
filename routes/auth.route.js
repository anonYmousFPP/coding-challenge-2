import {Router} from "express";

import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

import nodemailer from "nodemailer";
import User from "../database/user.schema.js"

import crypto from 'crypto';
import { validateLogin, validateSignup } from "../validators/auth.validators.js";
import logger from "../utils/logger.js";

import dotenv from "dotenv"
dotenv.config();

const route = Router();

import cloudinary from 'cloudinary';
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USERNAME,
      pass: process.env.EMAIL_PASSWORD
    }
});

const otpStorage = new Map();
const resetTokens = new Map();

function generateOTP() {
    return crypto.randomInt(100000, 999999).toString();
}

function generateResetToken() {
    return crypto.randomBytes(32).toString('hex');
}


route.post("/login", validateLogin, async (req, res) => {
    const {email, password} = req.body;
    if(!email || !password){
        logger.warn('Login attempt with missing credentials');
        res.send(`Email or password is not found`).status(404);
    }

    try{
        const user = await User.findOne({email});

        if(!user){
            logger.warn(`Login attempt with non-existent email: ${email}`);
            res.send(`User not found with this ${email}`).status(404);
        }

        const checkPassword = await bcrypt.compare(password, user.password);
        if(!checkPassword){
            logger.warn(`Invalid password attempt for user: ${email}`);
            res.send(`Incorrect Password`).status(400);
        }

        const jwtToken = jwt.sign({
            userId: user._id,
            email: user.email,
        }, process.env.JWT_SECRET);

        logger.info(`User logged in successfully`, { userId: user._id, email });
        return res.send({
            message: `Login Successfull`,
            token: jwtToken
        }).status(200);

    } catch (error) {
        logger.error('Login error', error);
        return res.status(500).send("Internal server error");
    }
})

route.post("/signup", validateSignup, async (req, res) => {
    const {name, email, password } = req.body;
    const file = req.files.photo;

    try{
        if(!name || !email || !password){
            logger.warn('Signup attempt with missing required fields');
            return res.send(`Name, email and password are required`).status(400);
        }
        const existingUser = await User.findOne({email});

        if(existingUser){
            logger.warn(`Signup attempt with existing email: ${email}`);
            return res.send(`User already exists with this email`).status(400);
        }

        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        cloudinary.uploader.upload(file.tempFilePath, async (result, err) => {
            if(err){
                logger.error('Cloudinary upload failed', err);
                return res.send(`Error is found ${err}`).status(400);
            }
            const newUser = new User({
                name,
                email,
                password : hashedPassword,
                photoUrl: result.secure_url,
            });
            await newUser.save();

        })

        logger.info('New user created successfully', {
            userId: newUser._id,
            email: newUser.email
        });
        return res.send({
            message: "User created successfully",
        }).status(200);
    }
    catch(err){
        logger.error('User signup failed', err);
        return res.status(500).send("Internal server error");
    }
})

route.post('/forget-password', async (req, res) => {
    try {
        const { email } = req.body;

        const user = await User.findOne({ email });
        if (!user) {
          logger.warn(`Forget password attempt for unregistered email: ${email}`);
          return res.status(404).json({
            success: false,
            message: 'If this email is registered, you will receive an OTP'
          });
        }

        const resetToken = generateResetToken();
        const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes expiry

        resetTokens.set(resetToken, { email, expiresAt });

        logger.info('Password reset initiated', { email });
        res.status(200).json({
          success: true,
          message: 'Password reset initiated',
          resetToken
        });
    } catch (error) {
        logger.error('Password reset initiation failed', error);
        res.status(500).json({
            success: false,
            message: 'Server error during password reset initiation'
        });
    }
})

route.post('/send-otp', async (req, res) => {
    try {
      const { resetToken } = req.body;

      const tokenData = resetTokens.get(resetToken);
      if (!tokenData) {
        logger.warn('Invalid reset token provided');
        return res.status(400).json({
          success: false,
          message: 'Invalid or expired reset token'
        });
      }

      const { email, expiresAt } = tokenData;

      if (Date.now() > expiresAt) {
        resetTokens.delete(resetToken);
        logger.warn('Expired reset token used');
        return res.status(400).json({
          success: false,
          message: 'Reset token expired'
        });
      }

      const otp = generateOTP();
      const otpExpiresAt = new Date(Date.now() + 5 * 60 * 1000); // OTP expires in 5 minutes

      otpStorage.set(resetToken, { otp, email, otpExpiresAt });

      const mailOptions = {
        from: process.env.EMAIL_USERNAME,
        to: email,
        subject: 'Password Reset OTP',
        text: `Your OTP for password reset is: ${otp}. This OTP is valid for 5 minutes.`
      };

      await transporter.sendMail(mailOptions);

      logger.info('OTP email sent successfully', { email });
      res.status(200).json({
        success: true,
        message: 'OTP sent to your registered email',
        resetToken
      });
    } catch (error) {
      logger.error('Failed to send OTP', error);
      res.status(500).json({
        success: false,
        message: 'Server error while sending OTP'
      });
    }
  });

  route.post('/verify-otp', async (req, res) => {
    try {
      const { resetToken, otp, newPassword } = req.body;

      const tokenData = resetTokens.get(resetToken);

      if (!tokenData) {
        logger.warn('Invalid reset token during OTP verification');
        return res.status(400).json({
          success: false,
          message: 'Invalid or expired reset token'
        });
      }

      const otpData = otpStorage.get(resetToken);
      if (!otpData) {
        logger.warn('OTP not found for provided token');
        return res.status(400).json({
          success: false,
          message: 'OTP not found or expired'
        });
      }

      const { otp: storedOtp, email, otpExpiresAt } = otpData;

      if (Date.now() > otpExpiresAt) {
        otpStorage.delete(resetToken);
        logger.warn('Expired OTP used');
        return res.status(400).json({
          success: false,
          message: 'OTP expired'
        });
      }

      if (otp !== storedOtp) {
        logger.warn('Invalid OTP provided');
        return res.status(400).json({
          success: false,
          message: 'Invalid OTP'
        });
      }

      const user = await User.findOne({ email });
      if (!user) {
        logger.error('User not found during password reset', { email });
        return res.status(404).json({
          success: false,
          message: 'User not found'
        });
      }

      const hashedPassword = await bcrypt.hash(newPassword, 12);

      user.password = hashedPassword;
      await user.save();

      resetTokens.delete(resetToken);
      otpStorage.delete(resetToken);

      logger.info('Password reset successfully completed', { email });
      res.status(200).json({
        success: true,
        message: 'Password updated successfully'
      });
    } catch (error) {
        logger.error('Password reset verification failed', error);
        res.status(500).json({
            success: false,
            message: 'Server error during password update'
        });
    }
});


route.get("/profile", async (req, res) => {
    try {
        const token = req.headers.authorization?.split(" ")[1];

        if (!token) {
            logger.warn('Unauthorized profile access - missing token');
            return res.status(401).json({
                success: false,
                message: "Authorization token required"
            });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        const user = await User.findById(decoded.userId).select("-password");

        if (!user) {
            logger.warn('Profile request for non-existent user', { userId: decoded.userId });
            return res.status(404).json({
                success: false,
                message: "User not found"
            });
        }

        logger.info('Profile retrieved successfully', { userId: user._id });
        return res.status(200).json({
            success: true,
            data: {
                name: user.name,
                email: user.email,
                photoUrl: user.photoUrl,
                createdAt: user.createdAt
            }
        });

    } catch (err) {
        logger.error('Profile access failed', err);
        if (err instanceof jwt.JsonWebTokenError) {
            return res.status(401).json({
                success: false,
                message: "Invalid token"
            });
        }
        return res.status(500).json({
            success: false,
            message: "Internal server error"
        });
    }
});

route.patch("/profile", async (req, res) => {
    try {
        const token = req.headers.authorization?.split(" ")[1];

        if (!token) {
            logger.warn('Unauthorized profile update - missing token');
            return res.status(401).json({
                success: false,
                message: "Authorization token required"
            });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        const user = await User.findById(decoded.userId);

        if (!user) {
            logger.warn('Profile update for non-existent user', { userId: decoded.userId });
            return res.status(404).json({
                success: false,
                message: "User not found"
            });
        }

        if (req.body.name) {
            user.name = req.body.name;
        }

        if (req.files?.photo) {
            const file = req.files.photo;

            const result = await new Promise((resolve, reject) => {
                cloudinary.uploader.upload(file.tempFilePath, (error, result) => {
                    if (error) reject(error);
                    else resolve(result);
                });
            });

            user.photoUrl = result.secure_url;
        }

        await user.save();

        logger.info('Profile updated successfully', { userId: user._id });
        return res.status(200).json({
            success: true,
            message: "Profile updated successfully",
            data: {
                name: user.name,
                photoUrl: user.photoUrl
            }
        });

    } catch (err) {
        logger.error('Profile update failed', err);
        if (err instanceof jwt.JsonWebTokenError) {
            return res.status(401).json({
                success: false,
                message: "Invalid token"
            });
        }
        return res.status(500).json({
            success: false,
            message: "Internal server error"
        });
    }
});


export default route;