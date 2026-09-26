const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const crypto = require("crypto");

const app = express();

app.use(cors({
  origin: true,
  methods: ["GET","POST","PUT","PATCH","DELETE","OPTIONS"],
  allowedHeaders: ["Content-Type","Authorization"]
}));
app.options("*", cors());
app.use(express.json({limit:"2mb"}));
app.use(express.urlencoded({extended:false}));

const PORT = process.env.PORT || 3000;
const MONGO_URL = process.env.MONGO_URL;
const JWT_SECRET = process.env.JWT_SECRET || "change-me";

function hashPassword(p){
  const salt=crypto.randomBytes(16).toString("hex");
  const hash=crypto.scryptSync(p,salt,64).toString("hex");
  return `${salt}:${hash}`;
}
function verifyPassword(p,stored){
  try{
    const [salt,hash]=String(stored).split(":");
    const test=crypto.scryptSync(p,salt,64).toString("hex");
    return crypto.timingSafeEqual(Buffer.from(test,"hex"),Buffer.from(hash,"hex"));
  }catch{return false;}
}
function emailOf(v){return String(v||"").trim().toLowerCase();}
function signUser(user){
  return jwt.sign({id:user._id.toString(),username:user.username,role:user.role},JWT_SECRET,{expiresIn:"30d"});
}
function publicUser(user){
  return {
    id:user._id, username:user.username, email:user.email, phone:user.phone,
    emailVerified:true, role:user.role, balance:user.balance,
    currency:user.currency, totalProfit:user.totalProfit,
    referralCode:user.referralCode, referredBy:user.referredBy||null,
    frozenAmount:Number(user.frozenAmount||0),
    creditPoints:Number(user.creditPoints||0),
    creditScore:Number(user.creditScore??100),
    avatarUrl:user.avatarUrl||""
  };
}

const UserSchema=new mongoose.Schema({
  username:{type:String,required:true,unique:true,trim:true},
  email:{type:String,required:true,unique:true,lowercase:true,trim:true},
  phone:{type:String,required:true,trim:true},
  emailVerified:{type:Boolean,default:true},
  passwordHash:{type:String,required:true},
  role:{type:String,default:"user"},
  balance:{type:Number,default:0},
  currency:{type:String,default:"USDT"},
  totalProfit:{type:Number,default:0},
  referralCode:{type:String,unique:true},
  referredBy:{type:String,default:null},
  frozenAmount:{type:Number,default:0},
  creditPoints:{type:Number,default:0},
  creditScore:{type:Number,default:100},
  avatarUrl:{type:String,default:""},
  createdAt:{type:Date,default:Date.now}
});
const ProductSchema=new mongoose.Schema({
  name:String,description:String,minAmount:Number,maxAmount:Number,
  dailyRate:Number,durationDays:Number,active:{type:Boolean,default:true}
});
const TransactionSchema=new mongoose.Schema({
  userId:mongoose.Schema.Types.ObjectId,type:String,amount:Number,
  method:String,details:Object,status:{type:String,default:"pending"},
  note:String,createdAt:{type:Date,default:Date.now},reviewedAt:Date
});
const MessageSchema=new mongoose.Schema({
  userId:mongoose.Schema.Types.ObjectId,subject:String,text:String,
  image:{type:String,default:""},
  sender:{type:String,default:"system"},
  read:{type:Boolean,default:false},createdAt:{type:Date,default:Date.now}
});

const User=mongoose.model("User",UserSchema);
const Product=mongoose.model("Product",ProductSchema);
const Transaction=mongoose.model("Transaction",TransactionSchema);
const Message=mongoose.model("Message",MessageSchema);

app.get("/",(req,res)=>res.json({success:true,service:"Zonguru Backend",status:"online",version:"live-chat-v1"}));

/* Registration: NO email verification and NO Resend */
app.post("/api/auth/register",async(req,res)=>{
  try{
    const body=req.body||{};
    const username=String(body.username||"").trim();
    const email=emailOf(body.email);
    const phone=String(body.phone||"").trim();
    const password=String(body.password||"");

    if(username.length<3)
      return res.status(400).json({success:false,message:"Username must be at least 3 characters"});
    if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
      return res.status(400).json({success:false,message:"Enter a valid email address"});
    if(phone.replace(/\D/g,"").length<6)
      return res.status(400).json({success:false,message:"Enter a valid phone number"});
    if(password.length<6)
      return res.status(400).json({success:false,message:"Password must be at least 6 characters"});

    if(await User.findOne({username}))
      return res.status(409).json({success:false,message:"Username is already registered"});
    if(await User.findOne({email}))
      return res.status(409).json({success:false,message:"This email is already registered"});

    let referralCode;
    do{
      referralCode="ZG"+crypto.randomBytes(4).toString("hex").toUpperCase();
    }while(await User.findOne({referralCode}));

    const user=await User.create({
      username,email,phone,emailVerified:true,
      passwordHash:hashPassword(password),referralCode
    });

    await Message.create({
      userId:user._id,
      subject:"Welcome to Zonguru",
      text:"Your Zonguru account has been created successfully."
    });

    res.json({
      success:true,message:"Registration successful",
      token:signUser(user),user:publicUser(user)
    });
  }catch(e){
    console.error("register",e);
    res.status(500).json({success:false,message:e.message||"Registration failed"});
  }
});

/* Login: username OR email + password */
app.post("/api/auth/login",async(req,res)=>{
  try{
    const username=String(req.body?.username||"").trim();
    const password=String(req.body?.password||"");
    const user=await User.findOne({
      $or:[{username},{email:emailOf(username)}]
    });
    if(!user||!verifyPassword(password,user.passwordHash))
      return res.status(401).json({success:false,message:"Invalid username/email or password"});

    if(!user.emailVerified){
      user.emailVerified=true;
      await user.save();
    }

    res.json({success:true,token:signUser(user),user:publicUser(user)});
  }catch(e){
    console.error("login",e);
    res.status(500).json({success:false,message:"Login failed"});
  }
});

function auth(req,res,next){
  try{
    const h=req.headers.authorization||"";
    const token=h.startsWith("Bearer ")?h.slice(7):"";
    if(!token)return res.status(401).json({success:false,message:"Unauthorized"});
    req.auth=jwt.verify(token,JWT_SECRET);
    next();
  }catch{
    res.status(401).json({success:false,message:"Invalid or expired token"});
  }
}
function admin(req,res,next){
  if(req.auth?.role!=="admin")
    return res.status(403).json({success:false,message:"Admin only"});
  next();
}

app.get("/api/me",auth,async(req,res)=>{
  const user=await User.findById(req.auth.id);
  if(!user)return res.status(404).json({success:false,message:"User not found"});
  res.json({success:true,user:publicUser(user)});
});

app.patch("/api/me/profile",auth,async(req,res)=>{
  try{
    const user=await User.findById(req.auth.id);
    if(!user)return res.status(404).json({success:false,message:"User not found"});

    const username=String(req.body?.username??user.username).trim();
    const email=emailOf(req.body?.email??user.email);
    const phone=String(req.body?.phone??user.phone).trim();
    const avatarUrl=String((req.body?.avatarUrl ?? user.avatarUrl) || "").trim();

    if(username.length<3)
      return res.status(400).json({success:false,message:"Username must be at least 3 characters"});
    if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
      return res.status(400).json({success:false,message:"Enter a valid email address"});
    if(phone.replace(/\D/g,"").length<6)
      return res.status(400).json({success:false,message:"Enter a valid phone number"});
    if(avatarUrl && avatarUrl.length>900000)
      return res.status(400).json({success:false,message:"Profile image is too large"});

    const otherUsername=await User.findOne({_id:{$ne:user._id},username});
    if(otherUsername)return res.status(409).json({success:false,message:"Username is already registered"});
    const otherEmail=await User.findOne({_id:{$ne:user._id},email});
    if(otherEmail)return res.status(409).json({success:false,message:"This email is already registered"});

    user.username=username;
    user.email=email;
    user.phone=phone;
    user.avatarUrl=avatarUrl;
    await user.save();

    res.json({success:true,message:"Profile updated successfully",user:publicUser(user)});
  }catch(e){
    console.error("profile update",e);
    res.status(500).json({success:false,message:e.message||"Profile update failed"});
  }
});

app.post("/api/auth/change-password",auth,async(req,res)=>{
  const user=await User.findById(req.auth.id);
  if(!user)return res.status(404).json({success:false,message:"User not found"});
  if(!verifyPassword(String(req.body?.currentPassword||""),user.passwordHash))
    return res.status(400).json({success:false,message:"Current password is incorrect"});
  const p=String(req.body?.newPassword||"");
  if(p.length<6)return res.status(400).json({success:false,message:"New password must be at least 6 characters"});
  user.passwordHash=hashPassword(p);
  await user.save();
  res.json({success:true,message:"Password changed"});
});

app.get("/api/products",auth,async(req,res)=>{
  res.json({success:true,products:await Product.find({active:true}).sort({createdAt:1})});
});

app.post("/api/products/:id/optimize",auth,async(req,res)=>{
  const p=await Product.findById(req.params.id);
  if(!p||!p.active)return res.status(404).json({success:false,message:"Product not found"});
  const amount=Number(req.body?.amount||0);
  if(amount<p.minAmount||amount>p.maxAmount)
    return res.status(400).json({success:false,message:"Amount is outside the product range"});
  res.json({
    success:true,product:p,
    estimatedProfit:amount*(Number(p.dailyRate||0)/100)*Number(p.durationDays||0)
  });
});

app.post("/api/deposits",auth,async(req,res)=>{
  const amount=Number(req.body?.amount||0);
  if(amount<=0)return res.status(400).json({success:false,message:"Invalid amount"});
  const t=await Transaction.create({
    userId:req.auth.id,type:"deposit",amount,
    method:String(req.body?.method||""),
    details:req.body?.details||{},
    note:String(req.body?.note||""),status:"pending"
  });
  res.json({success:true,transaction:t});
});

app.post("/api/withdrawals",auth,async(req,res)=>{
  const amount=Number(req.body?.amount||0);
  const user=await User.findById(req.auth.id);
  if(amount<=0)return res.status(400).json({success:false,message:"Invalid amount"});
  if(!user||user.balance<amount)
    return res.status(400).json({success:false,message:"Insufficient balance"});
  const t=await Transaction.create({
    userId:req.auth.id,type:"withdrawal",amount,
    method:String(req.body?.method||""),
    details:req.body?.details||{},
    note:String(req.body?.note||""),status:"pending"
  });
  res.json({success:true,transaction:t});
});

app.get("/api/transactions",auth,async(req,res)=>{
  res.json({success:true,transactions:await Transaction.find({userId:req.auth.id}).sort({createdAt:-1})});
});
app.get("/api/messages",auth,async(req,res)=>{
  res.json({success:true,messages:await Message.find({userId:req.auth.id}).sort({createdAt:-1})});
});
app.post("/api/messages/:id/read",auth,async(req,res)=>{
  await Message.updateOne({_id:req.params.id,userId:req.auth.id},{$set:{read:true}});
  res.json({success:true});
});

app.get("/api/chat",auth,async(req,res)=>{
  try{
    const messages=await Message.find({
      userId:req.auth.id,
      $or:[
        {subject:"Customer Service"},
        {sender:"admin"},
        {sender:"user"}
      ]
    }).sort({createdAt:1});
    const unread=messages.filter(m=>m.sender==="admin" && !m.read).length;
    await Message.updateMany(
      {userId:req.auth.id,sender:"admin",read:false},
      {$set:{read:true}}
    );
    res.json({success:true,messages,unread});
  }catch(e){
    console.error("chat load",e);
    res.status(500).json({success:false,message:"Unable to load customer service chat"});
  }
});

app.post("/api/chat/send",auth,async(req,res)=>{
  try{
    const text=String(req.body?.text||"").trim();
    const image=String(req.body?.image||"").trim();
    if(!text && !image)return res.status(400).json({success:false,message:"Message or image is required"});
    if(text.length>2000)return res.status(400).json({success:false,message:"Message is too long"});
    if(image && !/^data:image\/(jpeg|jpg|png|webp);base64,/i.test(image))return res.status(400).json({success:false,message:"Invalid image"});
    if(image.length>1600000)return res.status(400).json({success:false,message:"Image is too large"});
    const message=await Message.create({
      userId:req.auth.id,
      subject:"Customer Service",
      text,
      image,
      sender:"user",
      read:true,
      createdAt:new Date()
    });
    res.json({success:true,message});
  }catch(e){
    console.error("chat send",e);
    res.status(500).json({success:false,message:"Unable to send message"});
  }
});

app.get("/api/chat/notice",auth,async(req,res)=>{
  try{
    const unread=await Message.countDocuments({
      userId:req.auth.id,
      sender:"admin",
      read:false
    });
    res.json({success:true,unread});
  }catch(e){
    console.error("chat notice",e);
    res.status(500).json({success:false,message:"Unable to check chat notice"});
  }
});
app.get("/api/team",auth,async(req,res)=>{
  const user=await User.findById(req.auth.id);
  const members=await User.find({referredBy:user?.referralCode}).select("username email createdAt");
  res.json({success:true,referralCode:user?.referralCode,members});
});

/* Admin */
app.get("/api/admin/users",auth,admin,async(req,res)=>{
  res.json({success:true,users:await User.find().sort({createdAt:-1})});
});
app.get("/api/admin/transactions",auth,admin,async(req,res)=>{
  res.json({success:true,transactions:await Transaction.find().sort({createdAt:-1})});
});
app.post("/api/admin/transactions/:id/approve",auth,admin,async(req,res)=>{
  const t=await Transaction.findById(req.params.id);
  if(!t)return res.status(404).json({success:false,message:"Transaction not found"});
  if(t.status!=="pending")return res.status(400).json({success:false,message:"Transaction already reviewed"});
  const user=await User.findById(t.userId);
  if(!user)return res.status(404).json({success:false,message:"User not found"});
  if(t.type==="deposit")user.balance+=t.amount;
  if(t.type==="withdrawal"){
    if(user.balance<t.amount)return res.status(400).json({success:false,message:"Insufficient balance"});
    user.balance-=t.amount;
  }
  await user.save();
  t.status="approved";t.reviewedAt=new Date();await t.save();
  res.json({success:true,transaction:t,user:publicUser(user)});
});
app.post("/api/admin/transactions/:id/reject",auth,admin,async(req,res)=>{
  const t=await Transaction.findByIdAndUpdate(
    req.params.id,{status:"rejected",reviewedAt:new Date()},{new:true}
  );
  if(!t)return res.status(404).json({success:false,message:"Transaction not found"});
  res.json({success:true,transaction:t});
});
app.post("/api/admin/users/:id/balance",auth,admin,async(req,res)=>{
  const amount=Number(req.body?.amount||0);
  const user=await User.findById(req.params.id);
  if(!user)return res.status(404).json({success:false,message:"User not found"});
  user.balance+=amount;await user.save();
  res.json({success:true,user:publicUser(user)});
});
app.get("/api/admin/products",auth,admin,async(req,res)=>{
  res.json({success:true,products:await Product.find().sort({createdAt:1})});
});
app.post("/api/admin/products",auth,admin,async(req,res)=>{
  res.json({success:true,product:await Product.create(req.body)});
});
app.put("/api/admin/products/:id",auth,admin,async(req,res)=>{
  res.json({success:true,product:await Product.findByIdAndUpdate(req.params.id,req.body,{new:true})});
});
app.delete("/api/admin/products/:id",auth,admin,async(req,res)=>{
  await Product.findByIdAndDelete(req.params.id);
  res.json({success:true});
});
app.get("/api/admin/messages",auth,admin,async(req,res)=>{
  res.json({success:true,messages:await Message.find().sort({createdAt:-1})});
});
app.post("/api/admin/messages",auth,admin,async(req,res)=>{
  const userId=req.body?.userId;
  const text=String(req.body?.text||"").trim();
  if(!userId||!text)return res.status(400).json({success:false,message:"userId and text are required"});
  const m=await Message.create({
    userId,subject:String(req.body?.subject||"Customer Service"),
    text,sender:"admin",read:false
  });
  res.json({success:true,message:m});
});

app.get("/api/admin/chat/:userId",auth,admin,async(req,res)=>{
  try{
    const messages=await Message.find({userId:req.params.userId}).sort({createdAt:1});
    res.json({success:true,messages});
  }catch(e){
    res.status(500).json({success:false,message:"Unable to load chat"});
  }
});

app.post("/api/admin/chat/:userId/reply",auth,admin,async(req,res)=>{
  try{
    const text=String(req.body?.text||"").trim();
    if(!text)return res.status(400).json({success:false,message:"Reply is required"});
    const message=await Message.create({
      userId:req.params.userId,
      sender:"admin",
      text,
      read:false,
      createdAt:new Date()
    });
    res.json({success:true,message});
  }catch(e){
    res.status(500).json({success:false,message:"Unable to send reply"});
  }
});

async function start(){
  if(!MONGO_URL)throw new Error("MONGO_URL is not configured");
  await mongoose.connect(MONGO_URL);
  console.log("MongoDB connected successfully");
  app.listen(PORT,()=>console.log(`Zonguru backend running on port ${PORT}`));
}
start().catch(e=>{
  console.error("Startup error:",e);
  process.exit(1);
});
