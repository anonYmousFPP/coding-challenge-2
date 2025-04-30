import { Router } from "express";
import {
    login,
    signup,
    forgetPassword,
    sendOTP,
    verifyOTP,
    getProfile,
    updateProfile
} from "../controllers/auth.controller.js";
import { validateLogin, validateSignup } from "../validators/auth.validators.js";

const route = Router();

route.post("/login", validateLogin, login);
route.post("/signup", validateSignup, signup);
route.post('/forget-password', forgetPassword);
route.post('/send-otp', sendOTP);
route.post('/verify-otp', verifyOTP);
route.get("/profile", getProfile);
route.patch("/profile", updateProfile);

export default route;