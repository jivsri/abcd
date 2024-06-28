import express from "express";
import mongoose from "mongoose";
import jwt from "jsonwebtoken";
import path from "path";
import cookieParser from "cookie-parser";
import bcrypt from "bcrypt";


mongoose.connect("mongodb://localhost:27017",{
    dbName: "backend",
}).then(()=>{
    console.log("Database connected");
}).catch((err)=>{
    console.log("error detected",err);
});

const app=express();

app.use(express.static(path.join(path.resolve(),"public")));
app.use(express.json());
app.use(express.urlencoded({extended: true}));
app.use(cookieParser());

const userSchema=new mongoose.Schema({
    name: String,
    email: String,
    password: String,
});


const User=mongoose.model("users",userSchema);



const isAuthenticated=(req,res,next)=>{
    const {token}=req.cookies;
    if(!token) res.render("login.ejs");
    else next();
}

app.get("/",isAuthenticated,async(req,res)=>{
    const {token}=req.cookies;
    let decoded=jwt.decode(token,"abcdefghij");
    let user=await User.findById(decoded.id);
    res.render("logout.ejs",{name: user.name});
});

app.get("/register",(req,res)=>{
    res.render("register.ejs");
})


app.post("/register",async(req,res)=>{
    let {name,email,password}=req.body;
    let hashedPassword=await bcrypt.hash(password,10);
    let user=await User.create({name: name,email: email,password: hashedPassword});
    res.redirect("/");
});

app.post("/login",async(req,res)=>{
    let {email,password}=req.body;
    let user=await User.findOne({email});
    if(user){
        let boolCheck=await bcrypt.compare(password,user.password);
        console.log(boolCheck);
        if(boolCheck){
            const token=jwt.sign({id: user._id},"abcdefghij");
            res.cookie("token",token,{
                httpOnly: true,
                expires: new Date(Date.now()+60*1000),
            });
            res.redirect("/");
        }
        else res.render("login.ejs",{email:user.email ,message: "Incorrect password"})
    }
    else{
        res.redirect("/register");
    }
});


app.post("/logout",(req,res)=>{
    res.cookie("token",null,{
        expires: new Date(Date.now()),
    });
    res.redirect("/");
});






app.listen(5000,()=>{
    console.log("server connected");
})
