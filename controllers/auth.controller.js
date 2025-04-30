import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import nodemailer from "nodemailer";
import crypto from 'crypto';
import User from "../database/user.schema.js";
import logger from "../utils/logger.js";
import cloudinary from 'cloudinary';
import {
    successResponse,
    errorResponse,
    validationError,
    unauthorizedResponse,
    notFoundResponse,
    messages
} from "../utils/response.js";

import dotenv from "dotenv"
dotenv.config();

// Initialize Cloudinary
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

// Nodemailer transporter
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

export const login = async (req, res) => {
    const { email, password } = req.body;
    
    try {
        if (!email || !password) {
            logger.warn('Login attempt with missing credentials');
            return validationError(res, messages.MISSING_FIELDS);
        }

        const user = await User.findOne({ email });
        if (!user) {
            logger.warn(`Login attempt with non-existent email: ${email}`);
            return notFoundResponse(res, messages.USER_NOT_FOUND);
        }

        const checkPassword = await bcrypt.compare(password, user.password);
        if (!checkPassword) {
            logger.warn(`Invalid password attempt for user: ${email}`);
            return validationError(res, messages.INVALID_CREDENTIALS);
        }

        const jwtToken = jwt.sign({
            userId: user._id,
            email: user.email,
        }, process.env.JWT_SECRET);

        logger.info(`User logged in successfully`, { userId: user._id, email });
        return successResponse(res, { token: jwtToken }, messages.LOGIN_SUCCESS);

    } catch (error) {
        logger.error('Login error', error);
        return errorResponse(res, messages.SERVER_ERROR, 500, error);
    }
};

export const signup = async (req, res) => {
    const { name, email, password } = req.body;
    const file = req.files?.photo;

    try {
        if (!name || !email || !password) {
            logger.warn('Signup attempt with missing required fields');
            return validationError(res, messages.MISSING_FIELDS);
        }

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            logger.warn(`Signup attempt with existing email: ${email}`);
            return validationError(res, messages.USER_EXISTS);
        }

        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        if (!file) {
            const newUser = new User({
                name,
                email,
                password: hashedPassword
            });
            await newUser.save();
            
            logger.info('New user created successfully', {
                userId: newUser._id,
                email: newUser.email
            });
            return successResponse(res, null, messages.SIGNUP_SUCCESS);
        }

        cloudinary.uploader.upload(file.tempFilePath, async (result, err) => {
            if (err) {
                logger.error('Cloudinary upload failed', err);
                return errorResponse(res, messages.CLOUDINARY_ERROR, 400, err);
            }

            const newUser = new User({
                name,
                email,
                password: hashedPassword,
                photoUrl: result.secure_url,
            });
            await newUser.save();

            logger.info('New user created successfully', {
                userId: newUser._id,
                email: newUser.email
            });
            return successResponse(res, null, messages.SIGNUP_SUCCESS);
        });

    } catch (error) {
        logger.error('User signup failed', error);
        return errorResponse(res, messages.SERVER_ERROR, 500, error);
    }
};

export const forgetPassword = async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });
        
        if (!user) {
            logger.warn(`Forget password attempt for unregistered email: ${email}`);
            return successResponse(res, null, messages.RESET_INITIATED);
        }

        const resetToken = generateResetToken();
        const expiresAt = new Date(Date.now() + 5 * 60 * 1000);
        resetTokens.set(resetToken, { email, expiresAt });

        logger.info('Password reset initiated', { email });
        return successResponse(res, { resetToken }, messages.RESET_INITIATED);

    } catch (error) {
        logger.error('Password reset initiation failed', error);
        return errorResponse(res, messages.SERVER_ERROR, 500, error);
    }
};

export const sendOTP = async (req, res) => {
    try {
        const { resetToken } = req.body;
        const tokenData = resetTokens.get(resetToken);

        if (!tokenData) {
            logger.warn('Invalid reset token provided');
            return validationError(res, messages.RESET_TOKEN_INVALID);
        }

        const { email, expiresAt } = tokenData;
        if (Date.now() > expiresAt) {
            resetTokens.delete(resetToken);
            logger.warn('Expired reset token used');
            return validationError(res, messages.RESET_TOKEN_EXPIRED);
        }

        const otp = generateOTP();
        const otpExpiresAt = new Date(Date.now() + 5 * 60 * 1000);
        otpStorage.set(resetToken, { otp, email, otpExpiresAt });

        const mailOptions = {
            from: process.env.EMAIL_USERNAME,
            to: email,
            subject: 'Password Reset OTP',
            text: `Your OTP for password reset is: ${otp}. This OTP is valid for 5 minutes.`
        };

        await transporter.sendMail(mailOptions);
        logger.info('OTP email sent successfully', { email });
        return successResponse(res, { resetToken }, messages.OTP_SENT);

    } catch (error) {
        logger.error('Failed to send OTP', error);
        return errorResponse(res, messages.SERVER_ERROR, 500, error);
    }
};

export const verifyOTP = async (req, res) => {
    try {
        const { resetToken, otp, newPassword } = req.body;
        const tokenData = resetTokens.get(resetToken);

        if (!tokenData) {
            logger.warn('Invalid reset token during OTP verification');
            return validationError(res, messages.RESET_TOKEN_INVALID);
        }

        const otpData = otpStorage.get(resetToken);
        if (!otpData) {
            logger.warn('OTP not found for provided token');
            return validationError(res, messages.OTP_EXPIRED);
        }

        const { otp: storedOtp, email, otpExpiresAt } = otpData;
        if (Date.now() > otpExpiresAt) {
            otpStorage.delete(resetToken);
            logger.warn('Expired OTP used');
            return validationError(res, messages.OTP_EXPIRED);
        }

        if (otp !== storedOtp) {
            logger.warn('Invalid OTP provided');
            return validationError(res, messages.OTP_INVALID);
        }

        const user = await User.findOne({ email });
        if (!user) {
            logger.error('User not found during password reset', { email });
            return notFoundResponse(res, messages.USER_NOT_FOUND);
        }

        const hashedPassword = await bcrypt.hash(newPassword, 12);
        user.password = hashedPassword;
        await user.save();

        resetTokens.delete(resetToken);
        otpStorage.delete(resetToken);

        logger.info('Password reset successfully completed', { email });
        return successResponse(res, null, messages.PASSWORD_UPDATED);

    } catch (error) {
        logger.error('Password reset verification failed', error);
        return errorResponse(res, messages.SERVER_ERROR, 500, error);
    }
};

export const getProfile = async (req, res) => {
    try {
        const token = req.headers.authorization?.split(" ")[1];
        if (!token) {
            logger.warn('Unauthorized profile access - missing token');
            return unauthorizedResponse(res, messages.UNAUTHORIZED);
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.userId).select("-password");

        if (!user) {
            logger.warn('Profile request for non-existent user', { userId: decoded.userId });
            return notFoundResponse(res, messages.USER_NOT_FOUND);
        }

        logger.info('Profile retrieved successfully', { userId: user._id });
        return successResponse(res, {
            name: user.name,
            email: user.email,
            photoUrl: user.photoUrl,
            createdAt: user.createdAt
        }, messages.PROFILE_RETRIEVED);

    } catch (error) {
        logger.error('Profile access failed', error);
        if (error instanceof jwt.JsonWebTokenError) {
            return unauthorizedResponse(res, messages.INVALID_TOKEN);
        }
        return errorResponse(res, messages.SERVER_ERROR, 500, error);
    }
};

export const updateProfile = async (req, res) => {
    try {
        const token = req.headers.authorization?.split(" ")[1];
        if (!token) {
            logger.warn('Unauthorized profile update - missing token');
            return unauthorizedResponse(res, messages.UNAUTHORIZED);
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.userId);

        if (!user) {
            logger.warn('Profile update for non-existent user', { userId: decoded.userId });
            return notFoundResponse(res, messages.USER_NOT_FOUND);
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
        
        return successResponse(res, {
            name: user.name,
            photoUrl: user.photoUrl
        }, messages.PROFILE_UPDATED);

    } catch (error) {
        logger.error('Profile update failed', error);
        if (error instanceof jwt.JsonWebTokenError) {
            return unauthorizedResponse(res, messages.INVALID_TOKEN);
        }
        return errorResponse(res, messages.SERVER_ERROR, 500, error);
    }
};