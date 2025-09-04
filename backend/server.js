import express from "express";
import dotenv from "dotenv";
import connectDB from "./database/db.js";
import userRoute from "./routes/userRoute.js";
dotenv.config();
const app = express();

const PORT = process.env.PORT ||3000

//middleware
app.use(express.json());

//api routes
app.use("/user",userRoute)
//http://localhost:8000/user/register


app.listen(PORT,()=>{
    connectDB()
    console.log(`Server is running on port ${PORT}`);
})