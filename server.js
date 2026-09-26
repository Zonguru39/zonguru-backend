const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const crypto = require("crypto");

const app = express();
app.use(cors({ origin: true }));
app.use(express.json({ limit: "2mb" }));

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_THIS_JWT_SECRET";
const MONGO_URL = process.env.MONGO_URL;

if (!MONGO_URL) {
  console.error("ERROR: MONGO_URL is not set.");
  process.exit(1);
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  try {
    const [salt, storedHash] = stored.split(":");
    const hash = crypto.scryptSync(password, salt, 64).toString("hex");
    const a = Buffer.from(hash, "hex");
    const b = Buffer.from(storedHash, "hex");
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  } catch { return false; }
}

function emailOf(v) { return String(v || "").trim().toLowerCase(); }
function phoneOf(v) { return String(v || "").trim().replace(/[^\d+]/g, ""); }
function codeHash(v) { return crypto.createHash("sha256").update(String(v)).digest("hex"); }
function newCode() { return String(crypto.randomInt(100000, 1000000)); }

function sameHex(a, b) {
  try {
    const x = Buffer.from(a, "hex"), y = Buffer.from(b, "hex");
    return x.length === y.length && crypto.timingSafeEqual(x, y);
  } catch { return false; }
}

async function sendVerificationEmail(email, code) {
  const key = String(process.env.RESEND_API_KEY || "").trim();
  const from = String(process.env.EMAIL_FROM || "").trim();

  if (!key || !from) {
    throw new Error("Email service is not configured. Add RESEND_API_KEY and EMAIL_FROM in Render.");
  }

  const r = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${key}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      from,
      to: [email],
      subject: "Zonguru verification code",
      html: `<div style="font-family:Arial;padding:24px">
        <h2 style="color:#7657d9">Zonguru</h2>
        <p>Your verification code is:</p>
        <div style="font-size:32px;font-weight:bold;letter-spacing:8px">${code}</div>
        <p>This code expires in 10 minutes.</p>
      </div>`
    })
  });

  if (!r.ok) throw new Error("Email provider rejected the message.");
}

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, trim: true, minlength: 3 },
  email: { type: String, unique: true, sparse: true, lowercase: true, trim: true },
  phone: { type: String, default: "" },
  emailVerified: { type: Boolean, default: false },
  passwordHash: { type: String, required: true },
  role: { type: String, enum: ["user", "admin"], default: "user" },
  balance: { type: Number, default: 0 },
  currency: { type: String, default: "USDT" },
  totalProfit: { type: Number, default: 0 },
  referralCode: { type: String, unique: true, sparse: true },
  referredBy: { type: String, default: "" },
  createdAt: { type: Date, default: Date.now }
});

const verificationSchema = new mongoose.Schema({
  email: { type: String, required: true, lowercase: true, index: true },
  phone: { type: String, default: "" },
  codeHash: { type: String, required: true },
  expiresAt: { type: Date, required: true },
  attempts: { type: Number, default: 0 },
  lastSentAt: { type: Date, default: Date.now },
  createdAt: { type: Date, default: Date.now }
});

const productSchema = new mongoose.Schema({
  name: String, category: { type: String, default: "General" },
  price: Number, profitRate: Number, active: { type: Boolean, default: true }
});

const transactionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
  type: { type: String, enum: ["deposit", "withdraw", "optimize_profit", "optimize_cost"], required: true },
  amount: Number,
  status: { type: String, enum: ["pending", "approved", "rejected", "completed"], default: "pending" },
  note: { type: String, default: "" },
  method: { type: String, enum: ["crypto", "bank"], default: null },
  details: { type: mongoose.Schema.Types.Mixed, default: null },
  createdAt: { type: Date, default: Date.now }
});

const messageSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
  sender: { type: String, enum: ["system", "admin", "user"], default: "system" },
  text: { type: String, required: true },
  imageData: { type: String, default: "" },
  read: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model("User", userSchema);
const Verification = mongoose.model("EmailVerification", verificationSchema);
const Product = mongoose.model("Product", productSchema);
const Transaction = mongoose.model("Transaction", transactionSchema);
const Message = mongoose.model("Message", messageSchema);

function tokenFor(user) {
  return jwt.sign(
    { id: user._id.toString(), username: user.username, role: user.role },
    JWT_SECRET, { expiresIn: "7d" }
  );
}

function auth(req, res, next) {
  const h = req.headers.authorization || "";
  if (!h.startsWith("Bearer ")) return res.status(401).json({ success:false, message:"Login required" });
  try { req.user = jwt.verify(h.slice(7), JWT_SECRET); next(); }
  catch { return res.status(401).json({ success:false, message:"Invalid or expired token" }); }
}

function adminOnly(req, res, next) {
  if (req.user.role !== "admin") return res.status(403).json({success:false,message:"Admin access required"});
  next();
}

function publicUser(u) {
  return {
    id:u._id, username:u.username, email:u.email || "", phone:u.phone || "",
    emailVerified:!!u.emailVerified, role:u.role,
    balance:Number(u.balance||0), currency:u.currency,
    totalProfit:Number(u.totalProfit||0), referralCode:u.referralCode||""
  };
}

async function seed() {
  if (!(await Product.countDocuments())) {
    await Product.insertMany([
      {name:"Starter Product",category:"Starter",price:10,profitRate:.03},
      {name:"Standard Product",category:"Standard",price:25,profitRate:.05},
      {name:"Premium Product",category:"Premium",price:50,profitRate:.08},
      {name:"Pro Product",category:"Pro",price:100,profitRate:.12}
    ]);
  }
  const name = String(process.env.ADMIN_USERNAME || "admin").trim().toLowerCase();
  const pass = process.env.ADMIN_PASSWORD || "ChangeMe123!";
  let admin = await User.findOne({username:name});
  if (!admin) {
    await User.create({
      username:name,passwordHash:hashPassword(pass),role:"admin",
      balance:0,currency:"USDT",referralCode:"ADMIN",emailVerified:true
    });
  }
}

app.get("/", (req,res)=>res.json({success:true,service:"Zonguru Backend",status:"online"}));

/* ---------- EMAIL VERIFICATION ---------- */

app.post("/api/auth/send-email-code", async (req,res)=>{
  try {
    const email=emailOf(req.body.email), phone=phoneOf(req.body.phone);
    if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
      return res.status(400).json({success:false,message:"Enter a valid email address"});
    if(phone.replace(/\D/g,"").length<7)
      return res.status(400).json({success:false,message:"Enter a valid phone number"});
    if(await User.findOne({email}))
      return res.status(409).json({success:false,message:"This email is already registered"});

    const old=await Verification.findOne({email}).sort({createdAt:-1});
    if(old && Date.now()-old.lastSentAt.getTime()<60000)
      return res.status(429).json({success:false,message:"Please wait 60 seconds before requesting another code"});

    const code=newCode();
    await Verification.deleteMany({email});
    await Verification.create({
      email,phone,codeHash:codeHash(code),
      expiresAt:new Date(Date.now()+10*60*1000),lastSentAt:new Date()
    });
    await sendVerificationEmail(email,code);
    res.json({success:true,message:"Verification code sent to your email",expiresIn:600});
  } catch(e) {
    console.error("send-email-code",e);
    res.status(500).json({success:false,message:e.message||"Unable to send verification email"});
  }
});

/* ---------- REGISTER ---------- */

app.post("/api/auth/register", async (req,res)=>{
  try {
    const username=String(req.body.username||"").trim().toLowerCase();
    const password=String(req.body.password||"");
    const email=emailOf(req.body.email);
    const phone=phoneOf(req.body.phone);
    const emailCode=String(req.body.emailCode||"").trim();
    const referredBy=String(req.body.referralCode||"").trim().toUpperCase();

    if(username.length<3) return res.status(400).json({success:false,message:"Username must contain at least 3 characters"});
    if(password.length<6) return res.status(400).json({success:false,message:"Password must contain at least 6 characters"});
    if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({success:false,message:"Enter a valid email address"});
    if(phone.replace(/\D/g,"").length<7) return res.status(400).json({success:false,message:"Enter a valid phone number"});
    if(!/^\d{6}$/.test(emailCode)) return res.status(400).json({success:false,message:"Enter the 6-digit email verification code"});
    if(await User.findOne({username})) return res.status(409).json({success:false,message:"Username already registered"});
    if(await User.findOne({email})) return res.status(409).json({success:false,message:"Email already registered"});

    const v=await Verification.findOne({email}).sort({createdAt:-1});
    if(!v) return res.status(400).json({success:false,message:"Request a verification code first"});
    if(v.expiresAt.getTime()<Date.now()) {
      await Verification.deleteMany({email});
      return res.status(400).json({success:false,message:"Verification code expired. Request a new code"});
    }
    if(v.attempts>=5) return res.status(429).json({success:false,message:"Too many incorrect codes. Request a new code"});
    if(!sameHex(codeHash(emailCode),v.codeHash)) {
      v.attempts++; await v.save();
      return res.status(400).json({success:false,message:"Incorrect email verification code"});
    }

    const referralCode=`${username.slice(0,4).toUpperCase()}${crypto.randomBytes(3).toString("hex").toUpperCase()}`;
    const user=await User.create({
      username,email,phone,emailVerified:true,passwordHash:hashPassword(password),
      referralCode,referredBy
    });
    await Verification.deleteMany({email});
    await Message.create({userId:user._id,sender:"system",text:"Welcome to Zonguru. Your account is active."});

    res.status(201).json({success:true,message:"Registration successful",token:tokenFor(user),user:publicUser(user)});
  } catch(e) {
    console.error("register",e);
    res.status(500).json({success:false,message:"Registration failed"});
  }
});

/* ---------- LOGIN ---------- */

app.post("/api/auth/login", async (req,res)=>{
  try {
    const username=String(req.body.username||"").trim().toLowerCase();
    const password=String(req.body.password||"");
    const user=await User.findOne({username});
    if(!user || !verifyPassword(password,user.passwordHash))
      return res.status(401).json({success:false,message:"Invalid username or password"});
    res.json({success:true,message:"Login successful",token:tokenFor(user),user:publicUser(user)});
  } catch(e) {
    console.error("login",e);
    res.status(500).json({success:false,message:"Login failed"});
  }
});

app.get("/api/me",auth,async(req,res)=>{
  const u=await User.findById(req.user.id);
  if(!u)return res.status(404).json({success:false,message:"User not found"});
  res.json({success:true,user:publicUser(u)});
});

app.post("/api/auth/change-password",auth,async(req,res)=>{
  const oldPassword=String(req.body.oldPassword||""), newPassword=String(req.body.newPassword||"");
  if(newPassword.length<6)return res.status(400).json({success:false,message:"New password must contain at least 6 characters"});
  const u=await User.findById(req.user.id);
  if(!u||!verifyPassword(oldPassword,u.passwordHash))return res.status(400).json({success:false,message:"Current password is incorrect"});
  u.passwordHash=hashPassword(newPassword); await u.save();
  res.json({success:true,message:"Password changed successfully"});
});

/* ---------- PRODUCTS ---------- */

app.get("/api/products",auth,async(req,res)=>{
  res.json({success:true,products:await Product.find({active:true}).sort({price:1})});
});

app.post("/api/products/:id/optimize",auth,async(req,res)=>{
  try {
    const p=await Product.findOne({_id:req.params.id,active:true}), u=await User.findById(req.user.id);
    if(!p||!u)return res.status(404).json({success:false,message:"Product or user not found"});
    const cost=Number(p.price), profit=Number((cost*p.profitRate).toFixed(2));
    if(u.balance<cost)return res.status(400).json({success:false,message:`Insufficient balance. Required ${cost.toFixed(2)} ${u.currency}`});
    u.balance=Number((u.balance+profit).toFixed(2)); u.totalProfit=Number((u.totalProfit+profit).toFixed(2)); await u.save();
    await Transaction.create({userId:u._id,type:"optimize_profit",amount:profit,status:"completed",note:`${p.name} optimization`});
    res.json({success:true,message:"Product optimization completed",product:p.name,cost,profit,user:publicUser(u)});
  } catch(e) { console.error(e); res.status(500).json({success:false,message:"Optimization failed"}); }
});

/* ---------- DEPOSIT / WITHDRAW ---------- */

app.post("/api/deposits",auth,async(req,res)=>{
  const amount=Number(req.body.amount), note=String(req.body.note||"").trim();
  if(!Number.isFinite(amount)||amount<=0)return res.status(400).json({success:false,message:"Enter a valid deposit amount"});
  const tx=await Transaction.create({userId:req.user.id,type:"deposit",amount,status:"pending",note});
  await Message.create({userId:req.user.id,sender:"system",text:`Deposit request ${amount.toFixed(2)} USDT was submitted for review.`});
  res.status(201).json({success:true,message:"Deposit request submitted",transaction:tx});
});

app.post("/api/withdrawals",auth,async(req,res)=>{
  const amount=Number(req.body.amount), note=String(req.body.note||"").trim();
  const method=String(req.body.method||"crypto").toLowerCase(), details=req.body.details||{};
  if(!Number.isFinite(amount)||amount<=0)return res.status(400).json({success:false,message:"Enter a valid withdrawal amount"});
  if(!["crypto","bank"].includes(method))return res.status(400).json({success:false,message:"Choose Crypto or Bank"});
  if(method==="crypto"&&!String(details.walletAddress||"").trim())return res.status(400).json({success:false,message:"Enter your wallet address"});
  if(method==="bank"&&(!String(details.bankName||"").trim()||!String(details.accountName||"").trim()||!String(details.accountNumber||"").trim()))
    return res.status(400).json({success:false,message:"Enter bank name, account name and account number"});
  const u=await User.findById(req.user.id);
  if(!u||u.balance<amount)return res.status(400).json({success:false,message:"Insufficient balance"});
  const tx=await Transaction.create({userId:u._id,type:"withdraw",amount,status:"pending",note,method,details});
  await Message.create({userId:u._id,sender:"system",text:`Withdrawal request ${amount.toFixed(2)} USDT was submitted for review.`});
  res.status(201).json({success:true,message:"Withdrawal request submitted",transaction:tx});
});

/* ---------- TRANSACTIONS / MESSAGES / TEAM ---------- */

app.get("/api/transactions",auth,async(req,res)=>res.json({success:true,transactions:await Transaction.find({userId:req.user.id}).sort({createdAt:-1}).limit(100)}));
app.get("/api/messages",auth,async(req,res)=>res.json({success:true,messages:await Message.find({userId:req.user.id}).sort({createdAt:-1}).limit(100)}));
app.post("/api/messages/:id/read",auth,async(req,res)=>{await Message.updateOne({_id:req.params.id,userId:req.user.id},{$set:{read:true}});res.json({success:true})});

app.get("/api/team",auth,async(req,res)=>{
  const u=await User.findById(req.user.id);
  const members=await User.find({referredBy:String(u.referralCode||"").toUpperCase()}).select("username createdAt balance totalProfit").sort({createdAt:-1});
  res.json({success:true,referralCode:u.referralCode,members});
});

/* ---------- ADMIN ---------- */

app.get("/api/admin/users",auth,adminOnly,async(req,res)=>res.json({success:true,users:await User.find().select("-passwordHash").sort({createdAt:-1})}));
app.get("/api/admin/transactions",auth,adminOnly,async(req,res)=>res.json({success:true,transactions:await Transaction.find().sort({createdAt:-1}).limit(200)}));

app.post("/api/admin/transactions/:id/approve",auth,adminOnly,async(req,res)=>{
  const tx=await Transaction.findById(req.params.id); if(!tx||tx.status!=="pending")return res.status(400).json({success:false,message:"Transaction is not pending"});
  const u=await User.findById(tx.userId); if(!u)return res.status(404).json({success:false,message:"User not found"});
  if(tx.type==="deposit")u.balance=Number((u.balance+tx.amount).toFixed(2));
  if(tx.type==="withdraw"){if(u.balance<tx.amount){tx.status="rejected";await tx.save();return res.status(400).json({success:false,message:"User balance is insufficient"});}u.balance=Number((u.balance-tx.amount).toFixed(2));}
  tx.status="approved"; await u.save(); await tx.save();
  await Message.create({userId:u._id,sender:"admin",text:`${tx.type==="deposit"?"Deposit":"Withdrawal"} request was approved.`});
  res.json({success:true,message:"Transaction approved"});
});

app.post("/api/admin/transactions/:id/reject",auth,adminOnly,async(req,res)=>{
  const tx=await Transaction.findById(req.params.id); if(!tx||tx.status!=="pending")return res.status(400).json({success:false,message:"Transaction is not pending"});
  tx.status="rejected"; await tx.save();
  await Message.create({userId:tx.userId,sender:"admin",text:`${tx.type==="deposit"?"Deposit":"Withdrawal"} request was rejected.`});
  res.json({success:true,message:"Transaction rejected"});
});

app.post("/api/admin/users/:id/balance",auth,adminOnly,async(req,res)=>{
  const amount=Number(req.body.amount); if(!Number.isFinite(amount)||amount<0)return res.status(400).json({success:false,message:"Invalid balance"});
  const u=await User.findById(req.params.id); if(!u)return res.status(404).json({success:false,message:"User not found"});
  u.balance=amount; await u.save(); res.json({success:true,user:publicUser(u)});
});

mongoose.connect(MONGO_URL).then(async()=>{
  console.log("MongoDB connected successfully");
  await seed();
  app.listen(PORT,()=>console.log(`Zonguru backend running on port ${PORT}`));
}).catch(err=>{console.error("MongoDB connection failed:",err.message);process.exit(1);});
