import { verifyMail } from "../emailVerify/verifyMail.js";
import { Session } from "../models/sessionModel.js";
import { User } from "../models/userModel.js";
import bcrypt from "bcryptjs";
import jwt, { decode } from "jsonwebtoken";
import { sendOtpMail } from "../emailVerify/sendOtpMail.js";
export const registerUser = async(req,res)=>{
    try {
        const {username, email, password} = req.body;
        if(!username || !email || !password){
            return res.status(400).json({
                success: false,
                message: "All fields are required"
            })
        }
        //check if user already exists by email
        const existingUser = await User.findOne({email});
        if(existingUser){
            return res.status(400).json({
                success: false,
                message: "User already exists"
            })
        }
        //hash password
        const hashedPassword = await bcrypt.hash(password,10);
        //create new user
        const newUser = await User.create({
            username,
            email,
            password: hashedPassword
            });
        //generate token
        const token = jwt.sign({id: newUser._id}, process.env.SECRET_KEY, {expiresIn: "1h"});
        verifyMail(token, email)
        newUser.token = token;
        await newUser.save();
    
        res.status(201).json({
            success: true,
            message: "User registered successfully",
            data: newUser
        })
    } catch (error) {
        res.status(500).json({
            success: false,
            message: error.message
        })
    }
}
export const verification = async(req,res)=>{
    try {
        //token from header
        const authHeader = req.headers.authorization;
        if(!authHeader || !authHeader.startsWith("Bearer ")){
            return res.status(401).json({
                success: false,
                message: "Authorization token is missing or invalid"
            })
        }
        const token = authHeader.split(" ")[1];
        let decoded;
        try {
            decoded = jwt.verify(token, process.env.SECRET_KEY);
        } catch (err) {
            if (err.name === 'TokenExpiredError') {
                return res.status(401).json({
                    success: false,
                    message: "Token has expired"
                });
            }
            return res.status(401).json({
                success: false,
                message: "Token Verification failed"
            });
        }
        //find user by id in token 
        const user = await User.findById(decoded.id);
        if(!user){
            return res.status(404).json({
                success: false,
                message: "User not found"
            })
        }
        user.token = null;
        user.isVerified = true;
        await user.save();
        res.status(200).json({
            success: true,
            message: "Email verified successfully",
        })
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: error.message
        })
    }
}
export const loginUser = async(req,res)=>{
    try {
        const {email,password} = req.body;
        if(!email || !password){
            return res.status(400).json({
                success: false,
                message: "All fields are required"
            })
        }
        //check if user exists by email
        const user = await User.findOne({email});
        if(!user){
            return res.status(404).json({
                success: false,
                message: "User not found"
            })
        }
        //compare password
        const passwordCheck = await bcrypt.compare(password, user.password);
        if(!passwordCheck){
            return res.status(402).json({
                success: false,
                message: "Incorrect password"
            })
        }
        //check if user is verified
        if(user.isVerified !== true){
            return res.status(403).json({
                success: false,
                message: "Please verify your email to login"
            })
        }
        //check for existing session and delete it
        const existingSession = await Session.findOne({userId: user._id});
        if(existingSession){
            await Session.deleteOne({userId: user._id});
        }
        //create new session
        await Session.create({userId: user._id});

        //Generate tokens
        const accessToken = jwt.sign({id: user._id}, process.env.SECRET_KEY, {expiresIn: "10d"});
        const refreshToken = jwt.sign({id: user._id}, process.env.SECRET_KEY, {expiresIn: "30d"});
        user.isLoggedIn = true;
        await user.save();
        return res.status(200).json({
            success: true,
            message: `Welcome back ${user.username}`,
            accessToken,
            refreshToken,
            user
        })
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: error.message
        })
    }
}
export const logoutUser = async(req,res)=>{
    try {
        const userId = req.userId;
        await Session.deleteMany({userId});
        await User.findByIdAndUpdate(userId, {isLoggedIn: false});
        return res.status(200).json({
            success: true,
            message: "Logged out successfully"
        })
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: error.message
        })
    }
}
export const forgotPassword = async(req,res)=>{
    try {
        const {email} = req.body;
        const user = await User.findOne({email});
        if(!user){
            return res.status(404).json({
                success: false,
                message: "User not found"
            })
        }
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const expiry = new Date(Date.now() + 10 * 60 * 1000); //10 minutes from now
        user.otp = otp;
        user.otpExpiry = expiry;
        await user.save();
        //send otp to email
        await sendOtpMail(email, otp);
        return res.status(200).json({
            success: true,
            message: "OTP sent successfully"
        })
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: error.message
        })
    }
}