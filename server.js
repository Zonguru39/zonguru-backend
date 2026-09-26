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
app.options("/api/auth/send-email-code", cors());
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: false }));
app.use(express.text({ type: "text/plain", limit: "100kb" }));

const PORT = process.env.PORT || 3000;
const MONGO_URL = process.env.MONGO_URL;
const JWT_SECRET = process.env.JWT_SECRET || "change-me";
const RESEND_API_KEY = process.env.RESEND_API_KEY;
const EMAIL_FROM = process.env.EMAIL_FROM || "Zonguru <onboarding@resend.dev>";

function hashPassword(p) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(p, salt, 64).toString("hex");
  return `${salt}:${hash}`;
}
function verifyPassword(p, stored) {
  try {
    const [salt, hash] = String(stored).split(":");
    const test = crypto.scryptSync(p, salt, 64).toString("hex");
    return crypto.timingSafeEqual(Buffer.from(test,"hex"), Buffer.from(hash,"hex"));
  } catch { return false; }
}
function codeHash(code) {
  return crypto.createHash("sha256").update(String(code)).digest("hex");
}
function newCode() {
  return String(Math.floor(100000 + Math.random() * 900000));
}
function signUser(user) {
  return jwt.sign({ id: user._id.toString(), username: user.username, role: user.role }, JWT_SECRET, { expiresIn: "30d" });
}
function publicUser(user) {
  return {
    id: user._id,
    username: user.username,
    email: user.email,
    phone: user.phone,
    emailVerified: user.emailVerified,
    role: user.role,
    balance: user.balance,
    currency: user.currency,
    totalProfit: user.totalProfit,
    referralCode: user.referralCode,
    referredBy: user.referredBy || null
  };
}
function emailOf(v) { return String(v || "").trim().toLowerCase(); }
function phoneOf(v) { return String(v || "").trim(); }

async function sendVerificationEmail(to, code) {
  if (!RESEND_API_KEY) throw new Error("RESEND_API_KEY is not configured");
  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${RESEND_API_KEY}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      from: EMAIL_FROM,
      to: [to],
      subject: "Zonguru Email Verification Code",
      html: `<div style="font-family:Arial,sans-serif"><h2>Zonguru</h2><p>Your verification code is:</p><div style="font-size:32px;font-weight:700;letter-spacing:8px">${code}</div><p>This code expires in 10 minutes.</p></div>`
    })
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.message || data.error || `Resend HTTP ${response.status}`);
  return data;
}

const UserSchema = new mongoose.Schema({
  username: {type:String, required:true, unique:true, trim:true},
  email: {type:String, required:true, unique:true, lowercase:true, trim:true},
  phone: {type:String, required:true, trim:true},
  emailVerified: {type:Boolean, default:false},
  passwordHash: {type:String, required:true},
  role: {type:String, default:"user"},
  balance: {type:Number, default:0},
  currency: {type:String, default:"USDT"},
  totalProfit: {type:Number, default:0},
  referralCode: {type:String, unique:true},
  referredBy: {type:String, default:null},
  createdAt: {type:Date, default:Date.now}
});
const VerificationSchema = new mongoose.Schema({
  email: {type:String, required:true, index:true},
  phone: String,
  codeHash: String,
  expiresAt: Date,
  attempts: {type:Number, default:0},
  lastSentAt: Date,
  createdAt: {type:Date, default:Date.now}
});
const ProductSchema = new mongoose.Schema({
  name:String, description:String, minAmount:Number, maxAmount:Number,
  dailyRate:Number, durationDays:Number, active:{type:Boolean,default:true}
});
const TransactionSchema = new mongoose.Schema({
  userId:mongoose.Schema.Types.ObjectId, type:String, amount:Number,
  method:String, details:Object, status:{type:String,default:"pending"},
  note:String, createdAt:{type:Date,default:Date.now}, reviewedAt:Date
});
const MessageSchema = new mongoose.Schema({
  userId:mongoose.Schema.Types.ObjectId, subject:String, text:String,
  read:{type:Boolean,default:false}, createdAt:{type:Date,default:Date.now}
});

const User = mongoose.model("User", UserSchema);
const Verification = mongoose.model("Verification", VerificationSchema);
const Product = mongoose.model("Product", ProductSchema);
const Transaction = mongoose.model("Transaction", TransactionSchema);
const Message = mongoose.model("Message", MessageSchema);

app.get("/", (req,res)=>res.json({success:true,service:"Zonguru Backend",status:"online"}));

app.post("/api/auth/send-email-code", async (req,res)=>{
  try {
    let body = req.body;
    if (typeof body === "string") {
      try { body = JSON.parse(body); } catch {}
    }
    body = body || {};
    const email = emailOf(body.email);
    const phone = phoneOf(body.phone);

    if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
      return res.status(400).json({success:false,message:"Enter a valid email address"});
    if(phone.replace(/\D/g,"").length < 7)
      return res.status(400).json({success:false,message:"Enter a valid phone number"});
    if(await User.findOne({email}))
      return res.status(409).json({success:false,message:"This email is already registered"});

    const old = await Verification.findOne({email}).sort({createdAt:-1});
    if(old && old.lastSentAt && Date.now()-old.lastSentAt.getTime() < 60000)
      return res.status(429).json({success:false,message:"Please wait 60 seconds before requesting another code"});

    const code = newCode();
    await Verification.deleteMany({email});
    await Verification.create({
      email, phone, codeHash:codeHash(code),
      expiresAt:new Date(Date.now()+10*60*1000),
      lastSentAt:new Date()
    });
    await sendVerificationEmail(email, code);
    res.json({success:true,message:"Verification code sent to your email",expiresIn:600});
  } catch(e) {
    console.error("send-email-code",e);
    res.status(500).json({success:false,message:e.message || "Unable to send verification email"});
  }
});

app.post("/api/auth/register", async (req,res)=>{
  try {
    const body = req.body || {};
    const username = String(body.username || "").trim();
    const email = emailOf(body.email);
    const phone = phoneOf(body.phone);
    const emailCode = String(body.emailCode || "").trim();
    const password = String(body.password || "");

    if(username.length < 3) return res.status(400).json({success:false,message:"Username must be at least 3 characters"});
    if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({success:false,message:"Enter a valid email address"});
    if(phone.replace(/\D/g,"").length < 7) return res.status(400).json({success:false,message:"Enter a valid phone number"});
    if(password.length < 6) return res.status(400).json({success:false,message:"Password must be at least 6 characters"});
    if(!/^\d{6}$/.test(emailCode)) return res.status(400).json({success:false,message:"Enter the 6-digit verification code"});

    if(await User.findOne({username})) return res.status(409).json({success:false,message:"Username is already registered"});
    if(await User.findOne({email})) return res.status(409).json({success:false,message:"This email is already registered"});

    const v = await Verification.findOne({email}).sort({createdAt:-1});
    if(!v) return res.status(400).json({success:false,message:"Please request a verification code first"});
    if(v.expiresAt < new Date()) return res.status(400).json({success:false,message:"Verification code has expired"});
    if(v.attempts >= 5) return res.status(429).json({success:false,message:"Too many incorrect attempts. Request a new code"});
    if(v.codeHash !== codeHash(emailCode)) {
      v.attempts += 1;
      await v.save();
      return res.status(400).json({success:false,message:"Incorrect verification code"});
    }

    let referralCode;
    do {
      referralCode = "ZG" + crypto.randomBytes(4).toString("hex").toUpperCase();
    } while(await User.findOne({referralCode}));

    const user = await User.create({
      username,email,phone,emailVerified:true,
      passwordHash:hashPassword(password),
      referralCode
    });
    await Verification.deleteMany({email});
    await Message.create({
      userId:user._id,
      subject:"Welcome to Zonguru",
      text:"Your account has been verified successfully."
    });

    res.json({success:true,message:"Registration successful",token:signUser(user),user:publicUser(user)});
  } catch(e) {
    console.error("register",e);
    res.status(500).json({success:false,message:e.message || "Registration failed"});
  }
});

app.post("/api/auth/login", async (req,res)=>{
  try {
    const username = String(req.body?.username || "").trim();
    const password = String(req.body?.password || "");
    const user = await User.findOne({$or:[{username},{email:emailOf(username)}]});
    if(!user || !verifyPassword(password,user.passwordHash))
      return res.status(401).json({success:false,message:"Invalid username/email or password"});
    if(!user.emailVerified)
      return res.status(403).json({success:false,message:"Please verify your email first"});
    res.json({success:true,token:signUser(user),user:publicUser(user)});
  } catch(e) {
    console.error("login",e);
    res.status(500).json({success:false,message:"Login failed"});
  }
});

function auth(req,res,next){
  try {
    const h = req.headers.authorization || "";
    const token = h.startsWith("Bearer ") ? h.slice(7) : "";
    if(!token) return res.status(401).json({success:false,message:"Unauthorized"});
    req.auth = jwt.verify(token,JWT_SECRET);
    next();
  } catch { res.status(401).json({success:false,message:"Invalid or expired token"}); }
}
function admin(req,res,next){ if(req.auth?.role !== "admin") return res.status(403).json({success:false,message:"Admin only"}); next(); }

app.get("/api/me",auth,async(req,res)=>{
  const user=await User.findById(req.auth.id);
  if(!user) return res.status(404).json({success:false,message:"User not found"});
  res.json({success:true,user:publicUser(user)});
});
app.post("/api/auth/change-password",auth,async(req,res)=>{
  const user=await User.findById(req.auth.id);
  if(!user) return res.status(404).json({success:false,message:"User not found"});
  if(!verifyPassword(String(req.body?.currentPassword||""),user.passwordHash))
    return res.status(400).json({success:false,message:"Current password is incorrect"});
  const p=String(req.body?.newPassword||"");
  if(p.length<6) return res.status(400).json({success:false,message:"New password must be at least 6 characters"});
  user.passwordHash=hashPassword(p); await user.save();
  res.json({success:true,message:"Password changed"});
});

app.get("/api/products",auth,async(req,res)=>res.json({success:true,products:await Product.find({active:true}).sort({createdAt:1})}));
app.post("/api/products/:id/optimize",auth,async(req,res)=>{
  const p=await Product.findById(req.params.id);
  if(!p || !p.active) return res.status(404).json({success:false,message:"Product not found"});
  const amount=Number(req.body?.amount||0);
  if(amount<p.minAmount || amount>p.maxAmount) return res.status(400).json({success:false,message:"Amount is outside the product range"});
  res.json({success:true,product:p,estimatedProfit:amount*(Number(p.dailyRate||0)/100)*Number(p.durationDays||0)});
});
app.post("/api/deposits",auth,async(req,res)=>{
  const amount=Number(req.body?.amount||0);
  if(amount<=0) return res.status(400).json({success:false,message:"Invalid amount"});
  const t=await Transaction.create({userId:req.auth.id,type:"deposit",amount,method:String(req.body?.method||""),details:req.body?.details||{},note:String(req.body?.note||""),status:"pending"});
  res.json({success:true,transaction:t});
});
app.post("/api/withdrawals",auth,async(req,res)=>{
  const amount=Number(req.body?.amount||0);
  const user=await User.findById(req.auth.id);
  if(amount<=0) return res.status(400).json({success:false,message:"Invalid amount"});
  if(!user || user.balance<amount) return res.status(400).json({success:false,message:"Insufficient balance"});
  const t=await Transaction.create({userId:req.auth.id,type:"withdrawal",amount,method:String(req.body?.method||""),details:req.body?.details||{},note:String(req.body?.note||""),status:"pending"});
  res.json({success:true,transaction:t});
});
app.get("/api/transactions",auth,async(req,res)=>res.json({success:true,transactions:await Transaction.find({userId:req.auth.id}).sort({createdAt:-1})}));
app.get("/api/messages",auth,async(req,res)=>res.json({success:true,messages:await Message.find({userId:req.auth.id}).sort({createdAt:-1})}));
app.post("/api/messages/:id/read",auth,async(req,res)=>{await Message.updateOne({_id:req.params.id,userId:req.auth.id},{$set:{read:true}});res.json({success:true})});
app.get("/api/team",auth,async(req,res)=>{
  const user=await User.findById(req.auth.id);
  const members=await User.find({referredBy:user?.referralCode}).select("username email createdAt");
  res.json({success:true,referralCode:user?.referralCode,members});
});

app.get("/api/admin/users",auth,admin,async(req,res)=>res.json({success:true,users:await User.find().sort({createdAt:-1})}));
app.get("/api/admin/transactions",auth,admin,async(req,res)=>res.json({success:true,transactions:await Transaction.find().sort({createdAt:-1})}));
app.post("/api/admin/transactions/:id/approve",auth,admin,async(req,res)=>{
  const t=await Transaction.findById(req.params.id);
  if(!t) return res.status(404).json({success:false,message:"Transaction not found"});
  if(t.status!=="pending") return res.status(400).json({success:false,message:"Transaction already reviewed"});
  const user=await User.findById(t.userId);
  if(!user) return res.status(404).json({success:false,message:"User not found"});
  if(t.type==="deposit") user.balance += t.amount;
  if(t.type==="withdrawal") {
    if(user.balance<t.amount) return res.status(400).json({success:false,message:"Insufficient balance"});
    user.balance -= t.amount;
  }
  await user.save(); t.status="approved"; t.reviewedAt=new Date(); await t.save();
  res.json({success:true,transaction:t,user:publicUser(user)});
});
app.post("/api/admin/transactions/:id/reject",auth,admin,async(req,res)=>{
  const t=await Transaction.findByIdAndUpdate(req.params.id,{status:"rejected",reviewedAt:new Date()},{new:true});
  if(!t) return res.status(404).json({success:false,message:"Transaction not found"});
  res.json({success:true,transaction:t});
});
app.post("/api/admin/users/:id/balance",auth,admin,async(req,res)=>{
  const amount=Number(req.body?.amount||0);
  const user=await User.findById(req.params.id);
  if(!user) return res.status(404).json({success:false,message:"User not found"});
  user.balance += amount; await user.save();
  res.json({success:true,user:publicUser(user)});
});
app.get("/api/admin/products",auth,admin,async(req,res)=>res.json({success:true,products:await Product.find().sort({createdAt:1})}));
app.post("/api/admin/products",auth,admin,async(req,res)=>res.json({success:true,product:await Product.create(req.body)}));
app.put("/api/admin/products/:id",auth,admin,async(req,res)=>res.json({success:true,product:await Product.findByIdAndUpdate(req.params.id,req.body,{new:true})}));
app.delete("/api/admin/products/:id",auth,admin,async(req,res)=>{await Product.findByIdAndDelete(req.params.id);res.json({success:true})});
app.get("/api/admin/messages",auth,admin,async(req,res)=>res.json({success:true,messages:await Message.find().sort({createdAt:-1})}));
app.post("/api/admin/messages",auth,admin,async(req,res)=>{
  const userId=req.body?.userId;
  const text=String(req.body?.text||"").trim();
  if(!userId||!text) return res.status(400).json({success:false,message:"userId and text are required"});
  const m=await Message.create({userId,subject:String(req.body?.subject||"Customer Service"),text,read:false});
  res.json({success:true,message:m});
});

async function start(){
  if(!MONGO_URL) throw new Error("MONGO_URL is not configured");
  await mongoose.connect(MONGO_URL);
  console.log("MongoDB connected successfully");
  app.listen(PORT,()=>console.log(`Zonguru backend running on port ${PORT}`));
}
start().catch(e=>{console.error("Startup error:",e);process.exit(1);});
