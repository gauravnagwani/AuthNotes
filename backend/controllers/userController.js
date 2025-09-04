import { verifyMail } from "../emailVerify/verifyMail.js";
import { User } from "../models/userModel.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
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
