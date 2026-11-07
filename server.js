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
  const w=walletMap(user),cur=normCurrency(user.currency);
  const primaryUSDT=Number(w.USDT||0);
  return {
    id:user._id, username:user.username, email:user.email, phone:user.phone,
    emailVerified:true, role:user.role, balance:Number(convertCurrencyAmount(primaryUSDT,"USDT",cur).toFixed(2)),
    currency:cur, balances:{USDT:primaryUSDT}, totalProfit:user.totalProfit,
    referralCode:user.referralCode, referredBy:user.referredBy||null,
    frozenAmount:Number(user.frozenAmount||0),
    creditPoints:Number(user.creditPoints||0),
    referralBonus:Number(user.referralBonus||0),
    creditScore:Number(user.creditScore??100),
    vipLevel:Number(user.vipLevel||0),
    spinTickets:Number(user.spinTickets||0),
    avatarUrl:user.avatarUrl||""
  };
}

const UserSchema=new mongoose.Schema({
  username:{type:String,required:true,unique:true,trim:true},
  email:{type:String,required:true,unique:true,lowercase:true,trim:true},
  phone:{type:String,required:true,trim:true},
  emailVerified:{type:Boolean,default:true},
  passwordHash:{type:String,required:true},
  withdrawalPasswordHash:{type:String,default:""},
  bankAccounts:[{bankName:{type:String,required:true},accountName:{type:String,required:true},accountNumber:{type:String,required:true},additionalDetails:{type:String,default:""},createdAt:{type:Date,default:Date.now}}],
  role:{type:String,default:"user"},
  balance:{type:Number,default:0},
  currency:{type:String,default:"USDT"},
  balances:{type:mongoose.Schema.Types.Mixed,default:{}},
  totalProfit:{type:Number,default:0},
  referralCode:{type:String,unique:true},
  referredBy:{type:String,default:null},
  frozenAmount:{type:Number,default:0},
  creditPoints:{type:Number,default:0},
  referralBonus:{type:Number,default:0},
  creditScore:{type:Number,default:100},
  vipLevel:{type:Number,default:0,min:0,max:3},
  insufficientBalanceEnabled:{type:Boolean,default:false},
  insufficientBalanceTaskNumber:{type:Number,default:0,min:0,max:5},
  insufficientBalanceRequiredAmount:{type:Number,default:0,min:0},
  insufficientBalanceRemainingAmount:{type:Number,min:0},
  insufficientBalanceCommissionMultiplier:{type:Number,default:1,min:1,max:20},
  spinTickets:{type:Number,default:0,min:0},
  spinHistory:[{spinId:{type:String,required:true},prizeId:{type:String,required:true},label:{type:String,required:true},amount:{type:Number,default:0},creditedUSDT:{type:Number,default:0},claimStatus:{type:String,enum:["unclaimed","claimed"],default:"unclaimed"},createdAt:{type:Date,default:Date.now},claimedAt:{type:Date,default:null}}],
  luckySpinMode:{type:String,enum:["random","no_reward","usd10","usd50","usd1000","iphone18promax","five_tickets"],default:"random"},
  avatarUrl:{type:String,default:""},
  ownerAdminId:{type:String,default:null,index:true},
  ownerAdminUsername:{type:String,default:""},
  inviteCodeUsed:{type:String,default:""},
  recentTaskProductIds:[mongoose.Schema.Types.ObjectId],
  createdAt:{type:Date,default:Date.now}
});
const InviteCodeSchema=new mongoose.Schema({
  code:{type:String,unique:true,index:true},
  ownerAdminId:{type:String,default:null},
  ownerAdminUsername:{type:String,default:""},
  active:{type:Boolean,default:true},
  usedBy:{type:mongoose.Schema.Types.ObjectId,default:null},
  usedAt:{type:Date,default:null},
  useCount:{type:Number,default:0,min:0},
  lastUsedAt:{type:Date,default:null},
  createdAt:{type:Date,default:Date.now}
},{collection:"invite_codes",strict:false});
const InviteCode=mongoose.model("InviteCode",InviteCodeSchema);

const ProductSchema=new mongoose.Schema({
  name:String,description:String,category:String,
  price:{type:Number,default:0},profitRate:{type:Number,default:0},
  image:String,
  balanceGuardEnabled:{type:Boolean,default:false},
  specialTask:{type:Boolean,default:false},
  specialTaskNumber:{type:Number,default:0,min:0,max:5},
  specialRequiredAmount:{type:Number,default:0,min:0},
  specialCommissionMultiplier:{type:Number,default:1,min:1,max:20},
  requiredVip:{type:Number,default:0,min:0,max:3},
  minBalance:{type:Number,default:0},
  maxBalance:{type:Number,default:0},
  minAmount:Number,maxAmount:Number,
  dailyRate:Number,durationDays:Number,
  active:{type:Boolean,default:true},
  valueTier:{type:Number,default:3,min:1,max:5}
});
const TransactionSchema=new mongoose.Schema({
  userId:mongoose.Schema.Types.ObjectId,type:String,amount:Number,
  currency:{type:String,default:"USDT"},
  convertedAmountUSDT:{type:Number,default:null},
  method:String,details:Object,proofImage:{type:String,default:""},status:{type:String,default:"pending"},
  note:String,rejectionReason:{type:String,default:""},
  reserved:{type:Boolean,default:false},
  debitedCurrency:{type:String,default:""},debitedAmount:{type:Number,default:0},
  createdAt:{type:Date,default:Date.now},reviewedAt:Date
});
const BonusSchema=new mongoose.Schema({
 userId:{type:mongoose.Schema.Types.ObjectId,required:true,index:true},
 createdBy:{type:String,default:"admin"},
 title:{type:String,default:"Bonus"},
 message:{type:String,default:""},
 amountUSDT:{type:Number,required:true,min:0.01},
 expiresAt:{type:Date,required:true,index:true},
 status:{type:String,enum:["active","claimed","expired"],default:"active",index:true},
 claimedAt:{type:Date,default:null},
 createdAt:{type:Date,default:Date.now}
},{collection:"user_bonuses"});
const Bonus=mongoose.model("Bonus",BonusSchema);
const NotificationSchema=new mongoose.Schema({
  userId:{type:mongoose.Schema.Types.ObjectId,required:true,index:true},
  type:{type:String,default:"system",index:true},
  title:{type:String,default:""},
  text:{type:String,default:""},
  metadata:{type:mongoose.Schema.Types.Mixed,default:{}},
  read:{type:Boolean,default:false,index:true},
  createdAt:{type:Date,default:Date.now,index:true}
},{collection:"notifications"});
const Notification=mongoose.model("Notification",NotificationSchema);
const AdminActivitySchema=new mongoose.Schema({
  eventType:{type:String,enum:["register","login"],required:true,index:true},
  userId:{type:mongoose.Schema.Types.ObjectId,default:null,index:true},
  username:{type:String,default:""},email:{type:String,default:""},phone:{type:String,default:""},
  ip:{type:String,default:"unknown"},device:{type:String,default:"Unknown device"},
  ownerAdminId:{type:String,default:null,index:true},createdAt:{type:Date,default:Date.now,index:true}
},{collection:"admin_activity"});
const AdminActivity=mongoose.model("AdminActivity",AdminActivitySchema);
function requestDeviceDetails(req){
  const forwarded=String(req.headers["x-forwarded-for"]||"").split(",")[0].trim();
  const rawIp=forwarded||String(req.ip||req.socket?.remoteAddress||"unknown");
  return {ip:rawIp.replace(/^::ffff:/,"").slice(0,64),device:String(req.headers["user-agent"]||"Unknown device").slice(0,300)};
}
async function recordAdminActivity(eventType,user,req){
  try{
    const details=requestDeviceDetails(req);
    await AdminActivity.create({eventType,userId:user?._id||null,username:String(user?.username||"").slice(0,80),
      email:String(user?.email||"").slice(0,160),phone:String(user?.phone||"").slice(0,40),
      ip:details.ip,device:details.device,ownerAdminId:user?.ownerAdminId||null,createdAt:new Date()});
  }catch(e){console.error("admin activity record failed",eventType,e.message);}
}
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
const AnnouncementSchema=new mongoose.Schema({
  title:{type:String,default:""},
  text:{type:String,default:""},
  image:{type:String,default:""},
  audience:{type:String,enum:["all","selected"],default:"all",index:true},
  recipientIds:[{type:mongoose.Schema.Types.ObjectId,ref:"User"}],
  dismissedBy:[{type:mongoose.Schema.Types.ObjectId,ref:"User"}],
  active:{type:Boolean,default:true,index:true},
  createdBy:{type:String,default:"admin"},
  createdAt:{type:Date,default:Date.now}
});
const Announcement=mongoose.model("Announcement",AnnouncementSchema);
const TaskProgressSchema=new mongoose.Schema({
  userId:{type:mongoose.Schema.Types.ObjectId,unique:true},
  productIds:[mongoose.Schema.Types.ObjectId],
  completedIds:[mongoose.Schema.Types.ObjectId],
  recentProductIds:[mongoose.Schema.Types.ObjectId],
  currentProductId:{type:mongoose.Schema.Types.ObjectId,default:null},
  currentProductAmount:{type:Number,default:0},
  currentTaskNumber:{type:Number,default:0,min:0,max:5},
  startedAt:{type:Date,default:Date.now},
  updatedAt:{type:Date,default:Date.now}
});
const TaskProgress=mongoose.model("TaskProgress",TaskProgressSchema);
const OrderSchema=new mongoose.Schema({
  userId:mongoose.Schema.Types.ObjectId,
  productId:mongoose.Schema.Types.ObjectId,
  productName:String,amount:Number,profitRate:Number,commission:Number,
  baseCommission:{type:Number,default:0},
  commissionMultiplier:{type:Number,default:1},
  availableBalance:{type:Number,default:0},
  shortfall:{type:Number,default:0},
  taskNumber:{type:Number,default:0},
  reviewText:{type:String,default:""},
  status:{type:String,default:"completed"},
  createdAt:{type:Date,default:Date.now}
});
const Order=mongoose.model("Order",OrderSchema);
const PlatformSettingSchema=new mongoose.Schema({
  key:{type:String,unique:true,index:true},
  value:{type:mongoose.Schema.Types.Mixed,default:null},
  updatedAt:{type:Date,default:Date.now}
},{collection:"platform_settings"});
const PlatformSetting=mongoose.model("PlatformSetting",PlatformSettingSchema);



app.disable("x-powered-by");

app.get("/health",async(req,res)=>{
  try{
    if(mongoose.connection.readyState!==1)
      return res.status(503).json({success:false,service:"Zonguru Backend",status:"unhealthy",database:"disconnected"});
    await mongoose.connection.db.admin().ping();
    res.status(200).json({
      success:true,
      service:"Zonguru Backend",
      status:"online",
      database:"connected",
      timestamp:new Date().toISOString()
    });
  }catch(e){
    console.error("health check",e.message);
    res.status(503).json({success:false,service:"Zonguru Backend",status:"unhealthy",database:"error"});
  }
});

app.get("/",(req,res)=>res.json({success:true,service:"Zonguru Backend",status:"online",version:"live-chat-v1"}));

app.get("/api/public/events",async(req,res)=>{try{const setting=await PlatformSetting.findOne({key:"events_content"}).lean();res.set("Cache-Control","no-store");const v=setting?.value||{};res.json({success:true,event:{title:String(v.title||"Salary List"),text:String(v.text||""),image:String(v.image||""),updatedAt:setting?.updatedAt||null}})}catch(e){res.status(500).json({success:false,message:"Failed to load Events content"})}});
app.put("/api/internal/events",async(req,res)=>{try{const key=String(req.headers["x-deposit-settings-key"]||"");if(!process.env.DEPOSIT_SETTINGS_KEY||key!==process.env.DEPOSIT_SETTINGS_KEY)return res.status(401).json({success:false,message:"Unauthorized"});const title=String(req.body?.title||"").trim(),text=String(req.body?.text||"").trim(),image=String(req.body?.image||"").trim();if(title.length>120||text.length>8000)return res.status(400).json({success:false,message:"Title or event text is too long"});if(image&&(!/^data:image\/(png|jpeg|jpg|webp|gif);base64,/i.test(image)||image.length>1400000))return res.status(400).json({success:false,message:"Image must be PNG, JPG, WEBP or GIF and no larger than 1 MB"});const setting=await PlatformSetting.findOneAndUpdate({key:"events_content"},{$set:{value:{title,text,image},updatedAt:new Date()}},{upsert:true,new:true,setDefaultsOnInsert:true});res.json({success:true,event:setting.value,message:"Events content saved"})}catch(e){console.error("Save Events content:",e.message);res.status(500).json({success:false,message:"Failed to save Events content"})}});
app.get("/api/public/deposit-addresses",async(req,res)=>{
  try{
    const setting=await PlatformSetting.findOne({key:"deposit_addresses"}).lean();
    const defaults={
      "USDT-TRC20":"TS3fFhpyCECAtEnV7gurRyojgKVznieun5",
      "USDT-ERC20":"0x84a872810ab213eacb8ac8e9e962faf34cd9a72b",
      "ETH-ERC20":"0x84a872810ab213eacb8ac8e9e962faf34cd9a72b",
      "BTC-BTC":"176xzWWVLW5KsHoikVPatuinJJ6vMrvifW"
    };
    res.json({success:true,addresses:{...defaults,...(setting?.value||{})}});
  }catch(e){res.status(500).json({success:false,message:"Failed to load deposit addresses"});}
});

app.put("/api/internal/deposit-addresses",async(req,res)=>{
  try{
    const key=String(req.headers["x-deposit-settings-key"]||"");
    if(!process.env.DEPOSIT_SETTINGS_KEY || key!==process.env.DEPOSIT_SETTINGS_KEY)
      return res.status(401).json({success:false,message:"Unauthorized"});
    const body=req.body||{};
    const addresses={
      "USDT-TRC20":String(body["USDT-TRC20"]||"").trim(),
      "USDT-ERC20":String(body["USDT-ERC20"]||"").trim(),
      "ETH-ERC20":String(body["ETH-ERC20"]||"").trim(),
      "BTC-BTC":String(body["BTC-BTC"]||"").trim()
    };
    if(Object.values(addresses).some(v=>!v)) return res.status(400).json({success:false,message:"All deposit addresses are required."});
    const setting=await PlatformSetting.findOneAndUpdate(
      {key:"deposit_addresses"},
      {$set:{value:addresses,updatedAt:new Date()}},
      {upsert:true,new:true,setDefaultsOnInsert:true}
    );
    res.json({success:true,addresses:setting.value});
  }catch(e){
    console.error("Deposit address update:",e.message);
    res.status(500).json({success:false,message:"Failed to save deposit addresses"});
  }
});

/* Registration: NO email verification and NO Resend */
app.post("/api/auth/register",async(req,res)=>{
  try{
    const body=req.body||{};
    const username=String(body.username||"").trim();
    const email=emailOf(body.email);
    const phone=String(body.phone||"").trim();
    const password=String(body.password||"");
    const inviteCode=String(body.inviteCode||"").trim().toUpperCase();

    if(username.length<3)return res.status(400).json({success:false,message:"Username must be at least 3 characters"});
    if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))return res.status(400).json({success:false,message:"Enter a valid email address"});
    if(phone.replace(/\D/g,"").length<6)return res.status(400).json({success:false,message:"Enter a valid phone number"});
    if(password.length<6)return res.status(400).json({success:false,message:"Password must be at least 6 characters"});
    if(!inviteCode)return res.status(400).json({success:false,message:"Invite code is required to register"});

    if(await User.findOne({username}))return res.status(409).json({success:false,message:"Username is already registered"});
    if(await User.findOne({email}))return res.status(409).json({success:false,message:"This email is already registered"});

    // Admin invite codes are reusable until the main admin explicitly revokes them.
    // Existing one-time codes that were previously consumed (active=false + usedAt)
    // are also restored to reusable status by this rule.
    const adminInvite=await InviteCode.findOne({
      code:inviteCode,
      $or:[
        {active:true},
        {active:false,usedAt:{$ne:null}}
      ]
    });
    let referrer=null;
    let ownerAdminId=null;
    let ownerAdminUsername="";

    if(adminInvite){
      ownerAdminId=adminInvite.ownerAdminId||null;
      ownerAdminUsername=adminInvite.ownerAdminUsername||"";
    }else{
      referrer=await User.findOne({referralCode:inviteCode,role:"user"});
      if(!referrer)return res.status(400).json({success:false,message:"Invalid or inactive invite code"});
      ownerAdminId=referrer.ownerAdminId||null;
      ownerAdminUsername=referrer.ownerAdminUsername||"";
    }

    let referralCode;
    do{referralCode="ZG"+crypto.randomBytes(4).toString("hex").toUpperCase();}
    while(await User.findOne({referralCode}));

    const user=await User.create({
      username,email,phone,emailVerified:true,passwordHash:hashPassword(password),
      referralCode,
      referredBy:referrer?.referralCode||null,
      ownerAdminId,ownerAdminUsername,
      inviteCodeUsed:inviteCode,
      creditPoints:referrer?20:0,
      referralBonus:referrer?20:0
    });

    if(adminInvite){
      // Track usage without consuming the shared code.
      // $inc is atomic for a single MongoDB document.
      await InviteCode.updateOne(
        {_id:adminInvite._id},
        {
          $inc:{useCount:1},
          $set:{active:true,usedBy:adminInvite.usedBy||user._id,lastUsedAt:new Date()}
        }
      );
    }

    if(referrer){
      referrer.creditPoints=Number(referrer.creditPoints||0)+20;
      referrer.referralBonus=Number(referrer.referralBonus||0)+20;
      await referrer.save();
      await Message.create({
        userId:referrer._id,
        subject:"Referral Bonus",
        text:"A friend registered with your invite code. 20 bonus points have been added to your account."
      });
    }

    await Message.create({
      userId:user._id,
      subject:"Welcome to Zonguru",
      text:referrer
        ?"Welcome to Zonguru. Your invite was accepted and 20 bonus points have been added to your account."
        :"Your Zonguru account has been created successfully."
    });
    const registrationAt=new Date();
    const registrationDetails=requestDeviceDetails(req);
    await recordAdminActivity("register",user,req);
    // Private security notification for the newly registered account.
    try{
      await Notification.create({
        userId:user._id,type:"register_security",title:"New registration",
        text:"Your Zonguru account was registered successfully.",
        metadata:{registeredAt:registrationAt,device:registrationDetails.device,ip:registrationDetails.ip},
        read:false,createdAt:registrationAt
      });
    }catch(notificationError){console.error("registration security notification failed",notificationError.message);}
    // Broadcast a privacy-safe new-member alert to existing platform accounts only.
    // Registration IP/device details are never shared with other users.
    try{
      const recipientIds=await User.distinct("_id",{_id:{$ne:user._id},role:"user"});
      if(recipientIds.length){
        await Notification.insertMany(recipientIds.map(userId=>({
          userId,type:"new_user_registered",title:"New member joined",
          text:user.username+" has joined Zonguru.",
          metadata:{username:user.username},read:false,createdAt:registrationAt
        })),{ordered:false});
      }
    }catch(notificationError){console.error("new registration broadcast failed",notificationError.message);}
    res.json({success:true,message:"Registration successful",token:signUser(user),user:publicUser(user)});
  }catch(e){
    console.error("register",e);
    res.status(500).json({success:false,message:e.message||"Registration failed"});
  }
});
/* Login: username/email OR phone number + password */
app.post("/api/auth/login",async(req,res)=>{
  try{
    const username=String(req.body?.username||"").trim();
    const loginType=String(req.body?.loginType||"email").toLowerCase();
    const password=String(req.body?.password||"");
    let user=null;

    if(loginType==="phone"){
      const digits=username.replace(/\D/g,"");
      if(digits.length<6)
        return res.status(400).json({success:false,message:"Enter a valid phone number"});
      const phonePattern=new RegExp("^\\+?[\\s().-]*"+digits.split("").join("[\\s().-]*")+"$");
      const phoneMatches=await User.find({phone:phonePattern}).limit(2);
      if(phoneMatches.length>1)
        return res.status(409).json({success:false,message:"This phone number is linked to more than one account. Please use email or username."});
      user=phoneMatches[0]||null;
    }else{
      user=await User.findOne({
        $or:[{username},{email:emailOf(username)}]
      });
    }

    if(!user||!verifyPassword(password,user.passwordHash))
      return res.status(401).json({success:false,message:"Invalid login details or password"});

    if(!user.emailVerified){
      user.emailVerified=true;
      await user.save();
    }

    const loginAt=new Date();
    const requestDetails=requestDeviceDetails(req);
    const safeIp=requestDetails.ip;
    const ua=requestDetails.device;
    await recordAdminActivity("login",user,req);
    try{await Notification.create({userId:user._id,type:"login_security",title:"New login",text:"A login to your account was recorded.",metadata:{loginAt,device:ua,ip:safeIp}});}
    catch(logError){console.error("login security notification failed",logError.message);}
    res.json({success:true,token:signUser(user),user:publicUser(user)});
  }catch(e){
    console.error("login",e);
    res.status(500).json({success:false,message:"Login failed"});
  }
});

const SUPPORTED_CURRENCIES=["USDT","USD","MXN","EUR","GBP","CAD","AUD","JPY","CNY","SGD","THB","MYR","BRL","INR","EGP","ARS","PKR"];
// Rates are expressed as units of the currency per 1 USDT.
// Wallet balances remain stored in their native currency.
const CURRENCY_RATES={MXN:18.5,USD:1,EUR:0.86,GBP:0.75,CAD:1.38,AUD:1.51,JPY:148,CNY:7.1,SGD:1.28,THB:32.5,MYR:4.25,BRL:5.35,INR:88,EGP:51.75,ARS:1400,PKR:280};
function normCurrency(v){const x=String(v||"USDT").trim().toUpperCase();return SUPPORTED_CURRENCIES.includes(x)?x:"USDT";}
function convertCurrencyAmount(amount,fromCurrency,toCurrency){
  const n=Number(amount);
  const from=normCurrency(fromCurrency),to=normCurrency(toCurrency);
  if(!Number.isFinite(n))return 0;
  if(from===to)return n;
  const fromRate=from==="USDT"?1:Number(CURRENCY_RATES[from]||1);
  const toRate=to==="USDT"?1:Number(CURRENCY_RATES[to]||1);
  return (n/fromRate)*toRate;
}
function walletMap(user){
  const raw=(user.balances&&typeof user.balances==="object"&&!Array.isArray(user.balances))?user.balances:{};
  const keys=Object.keys(raw).filter(k=>SUPPORTED_CURRENCIES.includes(String(k).toUpperCase())&&Number.isFinite(Number(raw[k])));
  // USDT is the one canonical stored balance. If it exists, never add legacy
  // display-currency values to it, or the same funds can be counted twice.
  const usdtKey=keys.find(k=>String(k).toUpperCase()==="USDT");
  let primaryUSDT=0;
  if(usdtKey!==undefined){
    primaryUSDT=Number(raw[usdtKey]||0);
  }else if(keys.length){
    primaryUSDT=keys.reduce((sum,k)=>sum+convertCurrencyAmount(Number(raw[k]||0),k,"USDT"),0);
  }else{
    const cur=normCurrency(user.currency);
    const legacy=Number(user.balance||0);
    primaryUSDT=cur==="USDT"?legacy:convertCurrencyAmount(legacy,cur,"USDT");
  }
  return {USDT:Number(Number(primaryUSDT||0).toFixed(2))};
}
function normalizeWalletState(user){
  const w=walletMap(user);
  user.balances={USDT:Number(w.USDT||0)};
  user.balance=Number(w.USDT||0);
  return user.balances;
}
async function normalizeAllUserWallets(){
  const users=await User.find({}).lean();
  let fixed=0;
  for(const raw of users){
    const w=walletMap(raw);
    const next=Number(w.USDT||0);
    const before=Number(raw.balance||0);
    const beforeWallet=JSON.stringify(raw.balances||{});
    const normalized={USDT:next};
    const changed=before!==next || beforeWallet!==JSON.stringify(normalized);
    if(changed){
      await User.updateOne({_id:raw._id},{$set:{balances:normalized,balance:next}});
      fixed++;
    }
  }
  console.log("Primary USDT wallet synchronization complete:",fixed,"users normalized");
}
function setWalletBalance(user,currency,amount){
  const cur=normCurrency(currency),w=walletMap(user);
  const n=Number(amount);
  if(!Number.isFinite(n)||n<0)throw new Error("Invalid balance amount");
  w[cur]=Number(n.toFixed(2));
  user.balances={USDT:Number(w.USDT||0)};
  user.balance=Number(w.USDT||0);
}
function syncLegacyBalance(user){
  const w=walletMap(user);
  user.balances={USDT:Number(w.USDT||0)};
  user.balance=Number(w.USDT||0);
}
function applyInsufficientBalanceCredit(user, amountUSDT){
  const credit=Number(amountUSDT);
  if(!user || !user.insufficientBalanceEnabled || !Number.isFinite(credit) || credit<=0) return;
  const configured=Math.max(0,Number(user.insufficientBalanceRequiredAmount||0));
  const stored=Number(user.insufficientBalanceRemainingAmount);
  const remaining=Number.isFinite(stored) && stored>=0 ? stored : configured;
  user.insufficientBalanceRemainingAmount=Number(Math.max(0,remaining-credit).toFixed(2));
}
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

function yangonProfitWindows(now=new Date()){
  const parts=new Intl.DateTimeFormat("en-CA",{timeZone:"Asia/Yangon",year:"numeric",month:"2-digit",day:"2-digit"}).formatToParts(now);
  const p=Object.fromEntries(parts.map(x=>[x.type,x.value]));
  const y=Number(p.year),m=Number(p.month),d=Number(p.day),offsetMs=390*60*1000;
  const localMidnight=Date.UTC(y,m-1,d)-offsetMs;
  const weekday=new Date(Date.UTC(y,m-1,d)).getUTCDay();
  const daysSinceMonday=(weekday+6)%7;
  return {dayStart:new Date(localMidnight),weekStart:new Date(localMidnight-daysSinceMonday*86400000),monthStart:new Date(Date.UTC(y,m-1,1)-offsetMs)};
}
async function userProfitPeriods(userId,now=new Date()){
  const w=yangonProfitWindows(now);
  const queryStart=w.weekStart.getTime()<w.monthStart.getTime()?w.weekStart:w.monthStart;
  const rows=await Order.find({userId,status:"completed",createdAt:{$gte:queryStart}}).select("commission createdAt").lean();
  let today=0,week=0,month=0;
  for(const row of rows){const t=new Date(row.createdAt||0).getTime(),profit=Number(row.commission||0);if(!Number.isFinite(profit))continue;if(t>=w.monthStart.getTime())month+=profit;if(t>=w.weekStart.getTime())week+=profit;if(t>=w.dayStart.getTime())today+=profit;}
  return {todayProfit:Number(today.toFixed(2)),weeklyProfit:Number(week.toFixed(2)),monthlyProfit:Number(month.toFixed(2))};
}
app.get("/api/me/announcements",auth,async(req,res)=>{
  try{
    const rows=await Announcement.find({
      active:true,
      $or:[{audience:"all"},{audience:"selected",recipientIds:req.auth.id}]
    }).sort({createdAt:-1}).lean();
    res.json({success:true,announcements:rows.map(a=>({_id:a._id,title:a.title,text:a.text,image:a.image,createdAt:a.createdAt}))});
  }catch(e){console.error("load user announcements",e);res.status(500).json({success:false,message:"Unable to load announcements"});}
});
app.post("/api/me/announcements/:id/dismiss",auth,async(req,res)=>{
  try{
    const a=await Announcement.findOne({_id:req.params.id,active:true,$or:[{audience:"all"},{audience:"selected",recipientIds:req.auth.id}]}).select("_id").lean();
    if(!a)return res.status(404).json({success:false,message:"Announcement not found"});
    res.json({success:true,closed:true});
  }catch(e){console.error("close announcement",e);res.status(500).json({success:false,message:"Unable to close announcement"});}
});
app.get("/api/me",auth,async(req,res)=>{
  try{
    const user=await User.findById(req.auth.id);
    if(!user)return res.status(404).json({success:false,message:"User not found"});
    const profitPeriods=await userProfitPeriods(user._id);
    res.json({success:true,user:{...publicUser(user),...profitPeriods}});
  }catch(e){console.error("load user profit periods",e);res.status(500).json({success:false,message:"Unable to load account profit summary"});}
});

app.patch("/api/me/currency",auth,async(req,res)=>{
  try{
    const user=await User.findById(req.auth.id);
    if(!user)return res.status(404).json({success:false,message:"User not found"});
    const currency=normCurrency(req.body?.currency);
    // USDT is the primary account currency. Other currencies are display
    // currencies only and are calculated from the same primary USDT balance.
    user.currency=currency;
    syncLegacyBalance(user);
    await user.save();
    res.json({success:true,user:publicUser(user),currency:user.currency,balances:user.balances,balance:user.balance});
  }catch(e){
    console.error("currency update",e);
    res.status(500).json({success:false,message:e.message||"Currency update failed"});
  }
});

app.patch("/api/me/profile",auth,async(req,res)=>{
  try{
    const user=await User.findById(req.auth.id);
    if(!user)return res.status(404).json({success:false,message:"User not found"});

    const username=String(req.body?.username??user.username).trim();
    const email=emailOf(req.body?.email??user.email);
    const phone=String(req.body?.phone??user.phone).trim();
    const avatarUrl=String((req.body?.avatarUrl ?? user.avatarUrl) || "").trim();
    const currency=String(req.body?.currency ?? user.currency ?? "USDT").trim().toUpperCase();
    const allowedCurrencies=["USDT","MXN","USD","EUR","GBP","CAD","AUD","JPY","CNY","SGD","THB","MYR","BRL","INR","EGP","ARS","PKR"];
    if(!allowedCurrencies.includes(currency))
      return res.status(400).json({success:false,message:"Unsupported currency"});

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
    user.currency=currency;
    // Keep the legacy balance field synchronized with the selected wallet.
    // This makes the selected currency balance the real withdrawal balance,
    // instead of leaving user.balance pointing at the previous currency.
    syncLegacyBalance(user);
    await user.save();

    res.json({success:true,message:"Profile updated successfully",user:publicUser(user)});
  }catch(e){
    console.error("profile update",e);
    res.status(500).json({success:false,message:e.message||"Profile update failed"});
  }
});

app.post("/api/auth/change-password",auth,async(req,res)=>{
  try{
    const user=await User.findById(req.auth.id);
    if(!user)return res.status(404).json({success:false,message:"User not found"});
    const currentPassword=String(req.body?.currentPassword||"");
    const newPassword=String(req.body?.newPassword||"");
    if(!verifyPassword(currentPassword,user.passwordHash))
      return res.status(400).json({success:false,message:"Current password is incorrect"});
    if(newPassword.length<6)
      return res.status(400).json({success:false,message:"New password must be at least 6 characters"});
    if(newPassword===currentPassword)
      return res.status(400).json({success:false,message:"New password must be different from the current password"});

    const newHash=hashPassword(newPassword);
    user.passwordHash=newHash;
    await user.save();

    // Verify the persisted database value before confirming success.
    const saved=await User.findById(user._id).select("passwordHash");
    if(!saved || !verifyPassword(newPassword,saved.passwordHash))
      return res.status(500).json({success:false,message:"Password was not persisted. Please try again"});

    res.json({success:true,passwordChanged:true,message:"Password changed and saved"});
  }catch(e){
    console.error("change-password",e);
    res.status(500).json({success:false,message:"Password change failed. No partial change was confirmed"});
  }
});

app.get("/api/products",auth,async(req,res)=>{
  res.json({success:true,products:await Product.find({active:true}).sort({createdAt:1})});
});

app.get("/api/tasks/current",auth,async(req,res)=>{
  try{
    const user=await User.findById(req.auth.id);
    if(!user)return res.status(404).json({success:false,message:"User not found"});
    const vipLevel=Number(user.vipLevel||0);
    if(vipLevel<1)return res.json({success:true,task:null,locked:true,requiredVip:1,message:"VIP 1 is required to order products"});

    let task=await TaskProgress.findOne({userId:user._id});
    if(!task){
      task=await TaskProgress.create({
        userId:user._id,
        productIds:[],
        completedIds:[],
        recentProductIds:[],
        currentProductId:null,
        currentProductAmount:0,
        currentTaskNumber:1,
        updatedAt:new Date()
      });
    }

    const completedIds=Array.isArray(task.completedIds)?task.completedIds:[];
    const completed=completedIds.length;
    if(completed>=5){
      return res.json({success:true,task:{total:5,completed:5,currentTaskNumber:5,products:[]}});
    }

    const taskNumber=completed+1;
    const userRuleTriggered=
      Boolean(user.insufficientBalanceEnabled) &&
      Number(user.insufficientBalanceTaskNumber||0)===taskNumber &&
      Number(user.insufficientBalanceRequiredAmount||0)>0;
    const shortfall=userRuleTriggered?Math.max(0,Number(user.insufficientBalanceRemainingAmount ?? user.insufficientBalanceRequiredAmount ?? 0)):0;
    const accountCurrency=normCurrency(user.currency||"USDT");
    const wallet=walletMap(user);
    // The database wallet is canonical USDT. Convert it for display and
    // task-price calculations instead of reading a non-existent MXN wallet key.
    const balanceUSDT=Number(wallet.USDT||0);
    const balance=Number(convertCurrencyAmount(balanceUSDT,"USDT",accountCurrency).toFixed(2));
    const displayShortfall=Number(convertCurrencyAmount(shortfall,"USDT",accountCurrency).toFixed(2));

    let current=null;
    if(task.currentProductId){
      current=await Product.findOne({
        _id:task.currentProductId,
        active:true,
        requiredVip:{$lte:vipLevel}
      });
      if(!current){
        task.currentProductId=null;
        task.currentProductAmount=0;
        task.currentTaskNumber=0;
      }
    }

    // If the admin rule was changed after this product was created,
    // refresh the current amount so Task 3 immediately reflects the rule.
    if(current && userRuleTriggered){
      const desiredAmount=Math.round((balance+displayShortfall)*100)/100;
      if(Math.abs(Number(task.currentProductAmount||0)-desiredAmount)>0.009){
        task.currentProductAmount=desiredAmount;
        task.currentTaskNumber=taskNumber;
        task.updatedAt=new Date();
        await task.save();
      }
    }

    // Repair a previously-created task whose amount was stored as zero while
    // the selected display currency had no separate wallet key (e.g. MXN).
    if(current && !userRuleTriggered && Number(task.currentProductAmount||0)<=0 && balance>0){
      const tier=Math.max(1,Math.min(5,Number(current.valueTier||3)));
      const tierRanges={1:[0.15,0.45],2:[0.25,0.60],3:[0.35,0.72],4:[0.45,0.82],5:[0.55,0.90]};
      const range=tierRanges[tier]||tierRanges[3];
      const upper=Math.max(0,balance*range[1]);
      const lower=Math.max(0,Math.min(upper,balance*range[0]));
      task.currentProductAmount=Math.round((lower+Math.random()*Math.max(0,upper-lower))*100)/100;
      task.currentTaskNumber=taskNumber;
      task.updatedAt=new Date();
      await task.save();
    }

    if(!current){
      const recent=(task.recentProductIds||[]).map(String);
      const userRecent=(user.recentTaskProductIds||[]).map(String);
      const excluded=new Set([...recent,...completedIds.map(String),...userRecent]);

      let candidates=await Product.find({
        active:true,
        requiredVip:{$lte:vipLevel}
      }).lean();

      // If a fresh deployment has not run catalog seeding yet, seed it now.
      if(!candidates.length){
        await ensureProductCatalog();
        candidates=await Product.find({
          active:true,
          requiredVip:{$lte:vipLevel}
        }).lean();
      }

      if(!candidates.length){
        return res.status(503).json({
          success:false,
          code:"PRODUCT_CATALOG_EMPTY",
          message:"No active products are available right now. Please try again."
        });
      }

      // Product selection is intentionally independent from balance tier:
      // choose randomly from the full eligible catalog (70+ products when seeded).
      // Never fall back to an excluded product, so a previously shown product
      // cannot reappear while it is still in the user's recent history.
      const poolCandidates=candidates.filter(p=>!excluded.has(String(p._id)));
      if(!poolCandidates.length){
        return res.status(409).json({
          success:false,
          code:"PRODUCT_POOL_EXHAUSTED",
          message:"No new product is available in the current product pool. Please try again later."
        });
      }

      const picked=poolCandidates[Math.floor(Math.random()*poolCandidates.length)];
      current=await Product.findById(picked._id);
      if(!current){
        return res.status(503).json({
          success:false,
          code:"PRODUCT_SELECTION_FAILED",
          message:"Unable to select a product right now. Please try again."
        });
      }

      const tier=Math.max(1,Math.min(5,Number(current.valueTier||3)));
      const tierRanges={
        1:[0.15,0.45],
        2:[0.25,0.60],
        3:[0.35,0.72],
        4:[0.45,0.82],
        5:[0.55,0.90]
      };

      let amount=0;
      if(userRuleTriggered){
        amount=Math.round((balance+displayShortfall)*100)/100;
      }else{
        const range=tierRanges[tier]||tierRanges[3];
        const upper=Math.max(0,balance*range[1]);
        const lower=Math.max(0,Math.min(upper,balance*range[0]));
        amount=balance>0
          ? Math.round((lower+Math.random()*Math.max(0,upper-lower))*100)/100
          : 0;
      }
      if(amount<=0)amount=Math.round(Math.max(0,balance*0.5)*100)/100;

      task.currentProductId=current._id;
      task.currentProductAmount=amount;
      task.currentTaskNumber=taskNumber;
      task.recentProductIds=[...(task.recentProductIds||[]),current._id].slice(-15);
      task.updatedAt=new Date();
      await task.save();

      // Do not let an optional anti-repeat history write prevent the task
      // from loading for the user.
      try{
        user.recentTaskProductIds=[...(user.recentTaskProductIds||[]),current._id].slice(-25);
        await user.save();
      }catch(historyError){
        console.error("task recent-product history",historyError);
      }
    }

    const rate=Number(current.profitRate||current.dailyRate||0);
    const baseProfit=Number(task.currentProductAmount||0)*rate/100;
    const multiplier=userRuleTriggered
      ? Math.max(1,Math.min(20,Number(user.insufficientBalanceCommissionMultiplier||1)))
      : 1;

    const productPayload={
      id:current._id,
      name:current.name,
      description:current.description,
      category:current.category,
      price:Number(task.currentProductAmount||0),
      profitRate:rate,
      profitAmount:baseProfit*multiplier,
      image:current.image||"",
      requiredVip:Number(current.requiredVip||0),
      balanceGuardEnabled:Boolean(current.balanceGuardEnabled),
      specialTask:Boolean(current.specialTask),
      specialTaskNumber:Number(current.specialTaskNumber||0),
      specialRequiredAmount:Number(current.specialRequiredAmount||0),
      specialCommissionMultiplier:Number(current.specialCommissionMultiplier||1),
      insufficientBalance:userRuleTriggered,
      insufficientBalanceTaskNumber:userRuleTriggered?taskNumber:0,
      insufficientBalanceShortfall:userRuleTriggered?shortfall:0,
      insufficientBalanceRequiredAmount:userRuleTriggered?shortfall:0,
      insufficientBalanceCommissionMultiplier:userRuleTriggered?multiplier:1,
      completed:false,
      reviewSuggestions:getReviewSuggestions(current)
    };

    res.json({
      success:true,
      task:{
        total:5,
        completed,
        currentTaskNumber:taskNumber,
        products:[productPayload]
      }
    });
  }catch(e){
    console.error("task current",e?.stack||e);
    res.status(500).json({
      success:false,
      code:"TASK_LOAD_FAILED",
      message:"Unable to load task. Please try again."
    });
  }
});
function getReviewSuggestions(product){
  const text=((product?.name||"")+" "+(product?.description||"")+" "+(product?.category||"")).toLowerCase();
  if(/pen|stationery|paper|notebook|office/.test(text))
    return [
      "The product quality and design are very good. It is practical and easy to use.",
      "The item looks well made and matches the product description. I am satisfied with the overall quality.",
      "A useful product with a clean design and good finish. The product arrived as expected."
    ];
  if(/cable|cord|network|router|electronic|smart|tech|accessory/.test(text))
    return [
      "The product works well and the build quality feels good. It matches the listed specifications.",
      "The item is practical and performs as described. The design and quality are satisfactory.",
      "Good product quality and useful design. The product information was clear and matched the item."
    ];
  if(/home|wallpaper|furniture|kitchen|house/.test(text))
    return [
      "The product looks good and is practical for everyday use. The quality is satisfactory.",
      "The item matches the description and has a nice finish. Overall, I am satisfied with the product.",
      "A useful home product with good appearance and quality. It arrived as expected."
    ];
  return [
    "The product matches the description and the overall quality is good. I am satisfied with the item.",
    "The item looks well made and is as described. The quality and presentation are satisfactory.",
    "The product is practical and the quality is good. The item matched the information provided."
  ];
}

app.post("/api/tasks/:productId/complete",auth,async(req,res)=>{
  try{
    const task=await TaskProgress.findOne({userId:req.auth.id});
    if(!task)return res.status(404).json({success:false,message:"No active task"});
    if(!task.currentProductId||String(task.currentProductId)!==String(req.params.productId))return res.status(400).json({success:false,message:"This is not the current task product"});
    if((task.completedIds||[]).length>=5)return res.json({success:true,message:"Task already completed",completed:5,total:5,taskComplete:true});
    const user=await User.findById(req.auth.id),product=await Product.findById(req.params.productId);
    if(!user||!product)return res.status(404).json({success:false,message:"User or product not found"});
    if(Number(user.vipLevel||0)<Number(product.requiredVip||0))return res.status(403).json({success:false,message:"VIP level required",requiredVip:Number(product.requiredVip||0)});
    const amount=Number(task.currentProductAmount||0),rate=Number(product.profitRate||product.dailyRate||0);
    if(amount<=0)return res.status(400).json({success:false,message:"Product value is not configured"});
    const taskNumber=Number(task.completedIds.length||0)+1;
    const userRuleTriggered=Boolean(user.insufficientBalanceEnabled)&&Number(user.insufficientBalanceTaskNumber||0)===taskNumber&&Number(user.insufficientBalanceRequiredAmount||0)>0;
    const specialTriggered=userRuleTriggered,configuredShortfall=userRuleTriggered?Math.max(0,Number(user.insufficientBalanceRemainingAmount ?? user.insufficientBalanceRequiredAmount ?? 0)):0;
    const remainingShortfall=userRuleTriggered?Math.max(0,Number(user.insufficientBalanceRemainingAmount ?? user.insufficientBalanceRequiredAmount ?? 0)):0;
    const accountCurrency=normCurrency(user.currency||"USDT");
    const requiredBalanceUSDT=convertCurrencyAmount(amount,accountCurrency,"USDT");
    const requiredBalance=userRuleTriggered?requiredBalanceUSDT:(product.balanceGuardEnabled?requiredBalanceUSDT:0);
    const availableBalanceUSDT=Number(walletMap(user).USDT||0);
    const remainingShortfallUSDT=remainingShortfall;
    if((userRuleTriggered&&remainingShortfallUSDT>0)||(requiredBalance>0&&availableBalanceUSDT<requiredBalance)){
      const availableBalance=Number(convertCurrencyAmount(availableBalanceUSDT,"USDT",accountCurrency).toFixed(2)),difference=Math.max(convertCurrencyAmount(remainingShortfallUSDT,"USDT",accountCurrency),Math.max(0,amount-availableBalance));
      let pending=await Order.findOne({userId:user._id,productId:product._id,taskNumber,status:"pending"}).sort({createdAt:-1});
      if(!pending)pending=await Order.create({userId:user._id,productId:product._id,productName:product.name||"Product",amount,profitRate:rate,commission:0,baseCommission:amount*(rate/100),commissionMultiplier:1,availableBalance,shortfall:difference,taskNumber,reviewText:String(req.body?.reviewText||"").trim(),status:"pending"});
      return res.status(400).json({success:false,insufficientBalance:true,orderStatus:"pending",orderId:pending._id,specialTask:specialTriggered,message:"Insufficient balance. Please contact Customer Service.",orderAmount:amount,availableBalance,difference,shortfall:configuredShortfall||difference,taskNumber});
    }
    const reviewText=String(req.body?.reviewText||"").trim();
    if(reviewText.length>1000)return res.status(400).json({success:false,message:"Review is too long"});
    const baseCommission=amount*(rate/100),commissionMultiplier=specialTriggered?Math.max(1,Math.min(20,Number(user.insufficientBalanceCommissionMultiplier||1))):1,commission=baseCommission*commissionMultiplier;
    const commissionUSDT=Number(convertCurrencyAmount(commission,accountCurrency,"USDT").toFixed(2));
    task.completedIds.push(req.params.productId);if(task.completedIds.length>0&&task.completedIds.length%5===0){user.spinTickets=Number(user.spinTickets||0)+1;}task.productIds=[...(task.productIds||[]),req.params.productId].slice(-20);task.recentProductIds=[...(task.recentProductIds||[]),req.params.productId].slice(-15);task.currentProductId=null;task.currentProductAmount=0;task.currentTaskNumber=0;task.updatedAt=new Date();await task.save();
    await Order.create({userId:req.auth.id,productId:req.params.productId,productName:product.name||"Product",amount,profitRate:rate,commission,baseCommission,commissionMultiplier,availableBalance:Number(convertCurrencyAmount(availableBalanceUSDT,"USDT",accountCurrency).toFixed(2)),shortfall:0,taskNumber,reviewText,status:"completed"});
    // USDT remains the sole canonical stored balance. Convert the displayed
    // currency commission back to USDT before crediting the account.
    const wallet=walletMap(user);
    const creditedBalance=Number((Number(wallet.USDT||0)+commissionUSDT).toFixed(2));
    setWalletBalance(user,"USDT",creditedBalance);
    user.totalProfit=Number((Number(user.totalProfit||0)+commissionUSDT).toFixed(2));
    syncLegacyBalance(user);
    await user.save();
    const updatedUser=await User.findById(user._id);
    if(!updatedUser)throw new Error("Unable to update account balance");
    const finalWallet=walletMap(updatedUser);
    const completed=task.completedIds.length;
    res.json({
      success:true,completed,total:5,taskComplete:completed>=5,
      commission,
      commissionUSDT,
      creditedBalance:Number(convertCurrencyAmount(finalWallet.USDT||0,"USDT",accountCurrency).toFixed(2)),
      currency:accountCurrency,
      balances:finalWallet,
      totalProfit:Number(updatedUser.totalProfit||0),
      message:"Order completed successfully"
    });
  }catch(e){console.error("complete task",e);res.status(500).json({success:false,message:e.message||"Unable to complete order"});}
});
app.post("/api/products/:id/optimize",auth,async(req,res)=>{
  const p=await Product.findById(req.params.id),user=await User.findById(req.auth.id);
  if(!p||!p.active)return res.status(404).json({success:false,message:"Product not found"});
  if(!user)return res.status(404).json({success:false,message:"User not found"});
  if(Number(user.vipLevel||0)<Number(p.requiredVip||0))return res.status(403).json({success:false,message:"VIP level required",requiredVip:Number(p.requiredVip||0)});
  const taskProgress=await TaskProgress.findOne({userId:req.auth.id}),taskNumber=Number(taskProgress?.completedIds?.length||0)+1;
  if(!taskProgress?.currentProductId||String(taskProgress.currentProductId)!==String(p._id))return res.status(400).json({success:false,message:"This is not the current task product"});
  const amount=Number(taskProgress.currentProductAmount||0);
  if(amount<=0)return res.status(400).json({success:false,message:"Product value is not configured"});
  const userRuleTriggered=Boolean(user.insufficientBalanceEnabled)&&Number(user.insufficientBalanceTaskNumber||0)===taskNumber&&Number(user.insufficientBalanceRequiredAmount||0)>0;
  const specialTriggered=userRuleTriggered,requiredBalance=userRuleTriggered?amount:(p.balanceGuardEnabled?amount:0);
  if(requiredBalance>0&&Number(user.balance||0)<requiredBalance){
    const availableBalance=Number(user.balance||0),difference=Math.max(0,requiredBalance-availableBalance);
    let pending=await Order.findOne({userId:user._id,productId:p._id,taskNumber,status:"pending"}).sort({createdAt:-1});
    if(!pending)pending=await Order.create({userId:user._id,productId:p._id,productName:p.name||"Product",amount,profitRate:Number(p.profitRate||p.dailyRate||0),commission:0,baseCommission:amount*(Number(p.profitRate||p.dailyRate||0)/100),commissionMultiplier:1,availableBalance,shortfall:difference,taskNumber,status:"pending"});
    return res.status(400).json({success:false,insufficientBalance:true,orderStatus:"pending",orderId:pending._id,specialTask:specialTriggered,message:"Insufficient balance. Please contact Customer Service.",orderAmount:amount,availableBalance,difference,shortfall:difference,taskNumber});
  }
  const rate=Number(p.profitRate||p.dailyRate||0),baseEstimatedProfit=amount*(rate/100),commissionMultiplier=specialTriggered?Math.max(1,Math.min(20,Number(user.insufficientBalanceCommissionMultiplier||1))):1,estimatedProfit=baseEstimatedProfit*commissionMultiplier;
  res.json({success:true,product:p,amount,balanceGuardEnabled:Boolean(p.balanceGuardEnabled),profitRate:rate,estimatedProfit});
});
app.post("/api/deposits",auth,async(req,res)=>{
  try{
    const amount=Number(req.body?.amount);
    const requestedCurrency=String(req.body?.currency||"USDT").trim().toUpperCase();
    if(!Number.isFinite(amount)||amount<=0)return res.status(400).json({success:false,message:"Invalid amount"});
    // Reject unsupported currency codes instead of silently converting the request to USDT.
    if(!SUPPORTED_CURRENCIES.includes(requestedCurrency))return res.status(400).json({success:false,message:"Unsupported deposit currency"});
    const currency=requestedCurrency;
    const method=String(req.body?.method||"");
    const proofImage=String(req.body?.proofImage||"");
    if(!["bank","crypto"].includes(method))return res.status(400).json({success:false,message:"Choose a valid deposit method"});
    if(!proofImage.startsWith("data:image/")||proofImage.length>750000)return res.status(400).json({success:false,message:"Please attach a valid payment screenshot under the size limit"});
    const user=await User.findById(req.auth.id);
    if(!user)return res.status(404).json({success:false,message:"User not found"});
    const convertedAmountUSDT=Number(convertCurrencyAmount(amount,currency,"USDT").toFixed(2));
    const t=await Transaction.create({userId:user._id,type:"deposit",amount:Number(amount.toFixed(2)),currency,convertedAmountUSDT,method,details:req.body?.details||{},proofImage,note:String(req.body?.note||""),status:"pending",reserved:false});
    res.json({success:true,transaction:t});
  }catch(e){
    console.error("submit deposit",e);
    res.status(500).json({success:false,message:"Unable to submit deposit"});
  }
});

app.get("/api/me/withdrawal-security",auth,async(req,res)=>{
  try{
    const user=await User.findById(req.auth.id).select("withdrawalPasswordHash bankAccounts");
    if(!user)return res.status(404).json({success:false,message:"User not found"});
    res.json({success:true,withdrawalPasswordSet:Boolean(user.withdrawalPasswordHash),bankAccounts:(user.bankAccounts||[]).map(a=>({id:a._id,bankName:a.bankName,accountName:a.accountName,accountNumber:a.accountNumber,additionalDetails:a.additionalDetails||"",createdAt:a.createdAt}))});
  }catch(e){console.error("load withdrawal security",e);res.status(500).json({success:false,message:"Unable to load withdrawal settings"});}
});
app.post("/api/me/withdrawal-password",auth,async(req,res)=>{
  try{
    const password=String(req.body?.password||""),confirm=String(req.body?.confirmPassword||"");
    if(password.length<6||password.length>128)return res.status(400).json({success:false,message:"Withdrawal password must be 6 to 128 characters"});
    if(password!==confirm)return res.status(400).json({success:false,message:"Withdrawal passwords do not match"});
    const user=await User.findById(req.auth.id).select("+withdrawalPasswordHash");
    if(!user)return res.status(404).json({success:false,message:"User not found"});
    if(user.withdrawalPasswordHash)return res.status(409).json({success:false,message:"Withdrawal password is already set"});
    user.withdrawalPasswordHash=hashPassword(password);
    await user.save();
    const saved=await User.findById(user._id).select("withdrawalPasswordHash");
    if(!saved||!verifyPassword(password,saved.withdrawalPasswordHash))return res.status(500).json({success:false,message:"Could not verify saved withdrawal password"});
    res.json({success:true,withdrawalPasswordSet:true,message:"Withdrawal password saved"});
  }catch(e){console.error("set withdrawal password",e);res.status(500).json({success:false,message:"Unable to save withdrawal password"});}
});
app.post("/api/me/change-withdrawal-password",auth,async(req,res)=>{
  try{
    const currentPassword=String(req.body?.currentPassword||"");
    const newPassword=String(req.body?.newPassword||"");
    const confirmPassword=String(req.body?.confirmPassword||"");
    if(!currentPassword)return res.status(400).json({success:false,message:"Enter your current withdrawal password"});
    if(newPassword.length<6||newPassword.length>128)return res.status(400).json({success:false,message:"New withdrawal password must be 6 to 128 characters"});
    if(newPassword!==confirmPassword)return res.status(400).json({success:false,message:"New withdrawal passwords do not match"});
    if(newPassword===currentPassword)return res.status(400).json({success:false,message:"New withdrawal password must be different"});
    const user=await User.findById(req.auth.id).select("+withdrawalPasswordHash");
    if(!user)return res.status(404).json({success:false,message:"User not found"});
    if(!user.withdrawalPasswordHash)return res.status(409).json({success:false,code:"WITHDRAWAL_PASSWORD_REQUIRED",message:"No withdrawal password is set yet"});
    if(!verifyPassword(currentPassword,user.withdrawalPasswordHash))return res.status(401).json({success:false,code:"INVALID_WITHDRAWAL_PASSWORD",message:"Current withdrawal password is incorrect"});
    const updated=await User.updateOne({_id:user._id,withdrawalPasswordHash:user.withdrawalPasswordHash},{$set:{withdrawalPasswordHash:hashPassword(newPassword)}});
    if(!updated.modifiedCount)return res.status(409).json({success:false,message:"Withdrawal password changed by another request. Please retry"});
    const saved=await User.findById(user._id).select("+withdrawalPasswordHash");
    if(!saved||!verifyPassword(newPassword,saved.withdrawalPasswordHash))return res.status(500).json({success:false,message:"New withdrawal password could not be verified"});
    res.json({success:true,passwordChanged:true,message:"Withdrawal password changed successfully"});
  }catch(e){console.error("change withdrawal password",e);res.status(500).json({success:false,message:"Unable to change withdrawal password"});}
});

app.post("/api/me/change-withdrawal-password",auth,async(req,res)=>{
  try{
    const currentPassword=String(req.body?.currentPassword||"");
    const newPassword=String(req.body?.newPassword||"");
    const confirmPassword=String(req.body?.confirmPassword||"");
    if(!currentPassword)return res.status(400).json({success:false,message:"Enter your current withdrawal password"});
    if(newPassword.length<6||newPassword.length>128)return res.status(400).json({success:false,message:"New withdrawal password must be 6 to 128 characters"});
    if(newPassword!==confirmPassword)return res.status(400).json({success:false,message:"New withdrawal passwords do not match"});
    if(newPassword===currentPassword)return res.status(400).json({success:false,message:"New withdrawal password must be different"});
    const user=await User.findById(req.auth.id).select("+withdrawalPasswordHash");
    if(!user)return res.status(404).json({success:false,message:"User not found"});
    if(!user.withdrawalPasswordHash)return res.status(409).json({success:false,code:"WITHDRAWAL_PASSWORD_REQUIRED",message:"No withdrawal password is set yet"});
    if(!verifyPassword(currentPassword,user.withdrawalPasswordHash))return res.status(401).json({success:false,code:"INVALID_WITHDRAWAL_PASSWORD",message:"Current withdrawal password is incorrect"});
    const updated=await User.updateOne({_id:user._id,withdrawalPasswordHash:user.withdrawalPasswordHash},{$set:{withdrawalPasswordHash:hashPassword(newPassword)}});
    if(!updated.modifiedCount)return res.status(409).json({success:false,message:"Withdrawal password changed by another request. Please retry"});
    const saved=await User.findById(user._id).select("+withdrawalPasswordHash");
    if(!saved||!verifyPassword(newPassword,saved.withdrawalPasswordHash))return res.status(500).json({success:false,message:"New withdrawal password could not be verified"});
    res.json({success:true,passwordChanged:true,message:"Withdrawal password changed successfully"});
  }catch(e){console.error("change withdrawal password",e);res.status(500).json({success:false,message:"Unable to change withdrawal password"});}
});

app.post("/api/me/bank-accounts",auth,async(req,res)=>{
  try{
    const bankName=String(req.body?.bankName||"").trim(),accountName=String(req.body?.accountName||"").trim(),accountNumber=String(req.body?.accountNumber||"").trim(),additionalDetails=String(req.body?.additionalDetails||"").trim();
    if(!bankName||!accountName||!accountNumber)return res.status(400).json({success:false,message:"Bank name, account name and account number are required"});
    if(bankName.length>100||accountName.length>120||accountNumber.length>80||additionalDetails.length>500)return res.status(400).json({success:false,message:"Bank information is too long"});
    const user=await User.findById(req.auth.id).select("withdrawalPasswordHash bankAccounts");
    if(!user)return res.status(404).json({success:false,message:"User not found"});
    if(!user.withdrawalPasswordHash)return res.status(409).json({success:false,code:"WITHDRAWAL_PASSWORD_REQUIRED",message:"Set a withdrawal password before binding a bank account"});
    const duplicate=(user.bankAccounts||[]).some(a=>String(a.bankName||"").toLowerCase()===bankName.toLowerCase()&&String(a.accountNumber||"")===accountNumber);
    if(duplicate)return res.status(409).json({success:false,message:"This bank account is already bound"});
    user.bankAccounts=user.bankAccounts||[];
    user.bankAccounts.push({bankName,accountName,accountNumber,additionalDetails,createdAt:new Date()});
    await user.save();
    const accounts=(user.bankAccounts||[]).map(a=>({id:a._id,bankName:a.bankName,accountName:a.accountName,accountNumber:a.accountNumber,additionalDetails:a.additionalDetails||"",createdAt:a.createdAt}));
    res.json({success:true,bankAccounts:accounts,message:"Bank account bound successfully"});
  }catch(e){console.error("bind bank account",e);res.status(500).json({success:false,message:"Unable to bind bank account"});}
});

app.patch("/api/me/bank-accounts/:id",auth,async(req,res)=>{
  try{
    const bankName=String(req.body?.bankName||"").trim(),accountName=String(req.body?.accountName||"").trim(),accountNumber=String(req.body?.accountNumber||"").trim(),additionalDetails=String(req.body?.additionalDetails||"").trim();
    if(!bankName||!accountName||!accountNumber)return res.status(400).json({success:false,message:"Bank name, account name and account number are required"});
    if(bankName.length>100||accountName.length>120||accountNumber.length>80||additionalDetails.length>500)return res.status(400).json({success:false,message:"Bank information is too long"});
    const user=await User.findById(req.auth.id).select("bankAccounts");
    if(!user)return res.status(404).json({success:false,message:"User not found"});
    const account=(user.bankAccounts||[]).id(String(req.params.id||""));
    if(!account)return res.status(404).json({success:false,message:"Saved bank account not found"});
    const duplicate=(user.bankAccounts||[]).some(a=>String(a._id)!==String(account._id)&&String(a.bankName||"").toLowerCase()===bankName.toLowerCase()&&String(a.accountNumber||"")===accountNumber);
    if(duplicate)return res.status(409).json({success:false,message:"This bank account is already bound"});
    account.bankName=bankName;account.accountName=accountName;account.accountNumber=accountNumber;account.additionalDetails=additionalDetails;
    await user.save();
    const bankAccounts=(user.bankAccounts||[]).map(a=>({id:a._id,bankName:a.bankName,accountName:a.accountName,accountNumber:a.accountNumber,additionalDetails:a.additionalDetails||"",createdAt:a.createdAt}));
    res.json({success:true,bankAccounts,message:"Bank account updated successfully"});
  }catch(e){console.error("update bank account",e);res.status(500).json({success:false,message:"Unable to update bank account"});}
});

app.delete("/api/me/bank-accounts/:id",auth,async(req,res)=>{
 try{
  const user=await User.findById(req.auth.id).select("bankAccounts");
  if(!user)return res.status(404).json({success:false,message:"User not found"});
  const account=(user.bankAccounts||[]).id(String(req.params.id||""));
  if(!account)return res.status(404).json({success:false,message:"Saved bank account not found"});
  account.deleteOne();await user.save();
  const bankAccounts=(user.bankAccounts||[]).map(a=>({id:a._id,bankName:a.bankName,accountName:a.accountName,accountNumber:a.accountNumber,additionalDetails:a.additionalDetails||"",createdAt:a.createdAt}));
  res.json({success:true,bankAccounts,message:"Bank account deleted successfully"});
 }catch(e){console.error("delete bank account",e);res.status(500).json({success:false,message:"Unable to delete bank account"});}
});
app.post("/api/me/verify-withdrawal-password",auth,async(req,res)=>{
  try{
    const password=String(req.body?.password||"");
    if(!password)return res.status(400).json({success:false,message:"Enter your withdrawal password"});
    const user=await User.findById(req.auth.id).select("+withdrawalPasswordHash");
    if(!user)return res.status(404).json({success:false,message:"User not found"});
    if(!user.withdrawalPasswordHash)return res.status(409).json({success:false,code:"WITHDRAWAL_PASSWORD_REQUIRED",message:"Please set a withdrawal password first"});
    if(!verifyPassword(password,user.withdrawalPasswordHash))return res.status(401).json({success:false,code:"INVALID_WITHDRAWAL_PASSWORD",message:"Incorrect withdrawal password"});
    res.json({success:true,verified:true,message:"Withdrawal password verified successfully"});
  }catch(e){console.error("verify withdrawal password",e);res.status(500).json({success:false,message:"Unable to verify withdrawal password"});}
});

app.post("/api/withdrawals",auth,async(req,res)=>{
  const amount=Number(req.body?.amount||0),currency=normCurrency(req.body?.currency);
  const user=await User.findById(req.auth.id).select("+withdrawalPasswordHash");
  const withdrawalPassword=String(req.body?.withdrawalPassword||"");
  if(!user)return res.status(404).json({success:false,message:"User not found"});
  if(!user.withdrawalPasswordHash)return res.status(409).json({success:false,code:"WITHDRAWAL_PASSWORD_REQUIRED",message:"Please set a withdrawal password first"});
  if(!verifyPassword(withdrawalPassword,user.withdrawalPasswordHash))return res.status(401).json({success:false,code:"INVALID_WITHDRAWAL_PASSWORD",message:"Incorrect withdrawal password"});
  const method=String(req.body?.method||"").toLowerCase();
  let withdrawalDetails=req.body?.details||{};
  if(method==="bank"){
    const bankAccount=(user.bankAccounts||[]).id(String(req.body?.bankAccountId||""));
    if(!bankAccount)return res.status(409).json({success:false,code:"BANK_ACCOUNT_REQUIRED",message:"Please bind or select a bank account first"});
    withdrawalDetails={bankName:bankAccount.bankName,accountName:bankAccount.accountName,accountNumber:bankAccount.accountNumber,additionalDetails:bankAccount.additionalDetails||"",bankAccountId:String(bankAccount._id)};
  }else if(method!=="crypto")return res.status(400).json({success:false,message:"Choose a valid withdrawal method"});
  if(!Number.isFinite(amount)||amount<=0)return res.status(400).json({success:false,message:"Invalid amount"});
  const w=walletMap(user);
  const debitUSDT=Number(convertCurrencyAmount(amount,currency,"USDT").toFixed(2));
  const availableUSDT=Number(w.USDT||0);
  if(!Number.isFinite(debitUSDT)||debitUSDT<=0)return res.status(400).json({success:false,message:"Invalid converted withdrawal amount"});
  if(availableUSDT<debitUSDT)return res.status(400).json({
    success:false,message:"Insufficient balance",currency,
    availableBalance:Number(convertCurrencyAmount(availableUSDT,"USDT",currency).toFixed(2)),
    balances:{USDT:availableUSDT},accountCurrency:normCurrency(user.currency||"USDT")
  });
  setWalletBalance(user,"USDT",Number((availableUSDT-debitUSDT).toFixed(2)));
  syncLegacyBalance(user);
  await user.save();
  const t=await Transaction.create({
    userId:req.auth.id,type:"withdrawal",amount,currency,convertedAmountUSDT:debitUSDT,
    method,details:withdrawalDetails,
    note:String(req.body?.note||""),status:"pending",reserved:true,debitedCurrency:"USDT",debitedAmount:debitUSDT
  });
  res.json({success:true,transaction:t,user:publicUser(user),debitedCurrency:"USDT",debitedAmount:debitUSDT});
});

app.get("/api/orders",auth,async(req,res)=>{
  try{
    const orders=await Order.find({userId:req.auth.id}).sort({createdAt:-1});
    res.json({success:true,orders});
  }catch(e){res.status(500).json({success:false,message:"Unable to load order history"});}
});


app.post("/api/admin/notifications",auth,admin,async(req,res)=>{
 try{
  const title=String(req.body?.title||"Admin message").trim().slice(0,120);
  const message=String(req.body?.message||"").trim().slice(0,2000);
  if(!message)return res.status(400).json({success:false,message:"Notification message is required"});
  const target=String(req.body?.target||"all");let users;
  if(target==="all"){const filter={role:"user"};if(req.auth?.adminType!=="superadmin")filter.ownerAdminId=String(req.auth.id);users=await User.find(filter).select("_id").lean();}
  else{const ids=Array.isArray(req.body?.userIds)?req.body.userIds.map(String).filter(mongoose.isValidObjectId):[];if(!ids.length)return res.status(400).json({success:false,message:"Select at least one user"});const filter={_id:{$in:ids},role:"user"};if(req.auth?.adminType!=="superadmin")filter.ownerAdminId=String(req.auth.id);users=await User.find(filter).select("_id").lean();}
  if(!users.length)return res.status(400).json({success:false,message:"No eligible users found"});
  await Notification.insertMany(users.map(u=>({userId:u._id,type:"admin_message",title,text:message,metadata:{}})));
  res.json({success:true,count:users.length});
 }catch(e){console.error("admin notification",e);res.status(500).json({success:false,message:"Unable to send notification"});}
});

app.get("/api/admin/bonuses",auth,admin,async(req,res)=>{
 try{await Bonus.updateMany({status:"active",expiresAt:{$lte:new Date()},claimedAt:null},{$set:{status:"expired"}});const filter={};if(req.auth?.adminType!=="superadmin"){const ids=await User.find({role:"user",ownerAdminId:String(req.auth.id)}).distinct("_id");filter.userId={$in:ids};}const rows=await Bonus.find(filter).sort({createdAt:-1}).limit(500).lean();res.json({success:true,bonuses:rows});}
 catch(e){console.error("admin bonuses",e);res.status(500).json({success:false,message:"Unable to load bonuses"});}
});
app.post("/api/admin/bonuses",auth,admin,async(req,res)=>{
 try{
  const title=String(req.body?.title||"Bonus").trim().slice(0,120);
  const message=String(req.body?.message||"").trim().slice(0,2000);
  const amount=Number(req.body?.amountUSDT);
  const expiresAt=new Date(req.body?.expiresAt);
  const target=String(req.body?.target||"all");
  if(!Number.isFinite(amount)||amount<=0||amount>1000000)return res.status(400).json({success:false,message:"Enter a valid bonus amount in USDT"});
  if(!Number.isFinite(expiresAt.getTime())||expiresAt<=new Date())return res.status(400).json({success:false,message:"Expiry must be a future date and time"});
  let users;
  if(target==="all"){const filter={role:"user"};if(req.auth?.adminType!=="superadmin")filter.ownerAdminId=String(req.auth.id);users=await User.find(filter).select("_id").lean();}
  else{
   const ids=Array.isArray(req.body?.userIds)?req.body.userIds.map(String).filter(mongoose.isValidObjectId):[];
   if(!ids.length)return res.status(400).json({success:false,message:"Select at least one user"});
   const filter={_id:{$in:ids},role:"user"};if(req.auth?.adminType!=="superadmin")filter.ownerAdminId=String(req.auth.id);users=await User.find(filter).select("_id").lean();
  }
  if(!users.length)return res.status(400).json({success:false,message:"No eligible users found"});
  const docs=users.map(u=>({userId:u._id,createdBy:String(req.auth?.id||"admin"),title,message,amountUSDT:Number(amount.toFixed(2)),expiresAt,status:"active"}));
  const created=await Bonus.insertMany(docs);
  await Notification.insertMany(users.map(u=>({userId:u._id,type:"bonus_reward",title,text:message||"A cash bonus is available. Open Notifications to claim it.",metadata:{bonusId:String(created.find(x=>String(x.userId)===String(u._id))._id),amountUSDT:Number(amount.toFixed(2)),expiresAt}})));
  res.json({success:true,count:created.length});
 }catch(e){console.error("create bonuses",e);res.status(500).json({success:false,message:"Unable to create bonuses"});}
});
app.get("/api/me/bonuses",auth,async(req,res)=>{
 try{
  const now=new Date();
  await Bonus.updateMany({userId:req.auth.id,status:"active",expiresAt:{$lte:now},claimedAt:null},{$set:{status:"expired"}});
  const rows=await Bonus.find({userId:req.auth.id}).sort({createdAt:-1}).limit(100).lean();
  res.set("Cache-Control","no-store");res.json({success:true,bonuses:rows});
 }catch(e){res.status(500).json({success:false,message:"Unable to load bonuses"});}
});
app.post("/api/me/bonuses/:id/claim",auth,async(req,res)=>{
 let session;
 try{
  session=await mongoose.startSession();let result;
  await session.withTransaction(async()=>{
   const now=new Date();
   const bonus=await Bonus.findOne({_id:req.params.id,userId:req.auth.id}).session(session);
   if(!bonus)throw Object.assign(new Error("Bonus not found"),{status:404});
   if(bonus.status==="claimed"||bonus.claimedAt)throw Object.assign(new Error("Bonus already claimed"),{status:409});
   if(bonus.status==="expired"||bonus.expiresAt<=now){
    await Bonus.updateOne({_id:bonus._id,userId:req.auth.id,status:"active"},{$set:{status:"expired"}},{session});
    throw Object.assign(new Error("Bonus has expired"),{status:410});
   }
   const claimed=await Bonus.updateOne({_id:bonus._id,userId:req.auth.id,status:"active",claimedAt:null,expiresAt:{$gt:now}},{$set:{status:"claimed",claimedAt:now}},{session});
   if(!claimed.modifiedCount)throw Object.assign(new Error("Bonus is no longer available"),{status:409});
   const user=await User.findById(req.auth.id).session(session);
   if(!user)throw Object.assign(new Error("User not found"),{status:404});
   const wallet=walletMap(user),amount=Number(bonus.amountUSDT);
   setWalletBalance(user,"USDT",Number((Number(wallet.USDT||0)+amount).toFixed(2)));
   syncLegacyBalance(user);await user.save({session});
   await Transaction.create([{userId:user._id,type:"bonus",amount,currency:"USDT",convertedAmountUSDT:amount,status:"approved",note:"Bonus claimed: "+bonus.title,reviewedAt:now}],{session});
   result={amountUSDT:amount,bonusId:String(bonus._id),user:publicUser(user)};
  });
  res.json({success:true,...result});
 }catch(e){console.error("claim bonus",e);res.status(e.status||500).json({success:false,message:e.message||"Unable to claim bonus"});}
 finally{if(session)await session.endSession();}
});

app.get("/api/me/notifications",auth,async(req,res)=>{
  try{
    const rows=await Notification.find({userId:req.auth.id}).sort({createdAt:-1}).limit(100).lean();
    const unreadCount=await Notification.countDocuments({userId:req.auth.id,read:false});
    res.set("Cache-Control","no-store");
    res.json({success:true,notifications:rows,unreadCount});
  }catch(e){console.error("load notifications",e);res.status(500).json({success:false,message:"Unable to load notifications"});}
});
app.post("/api/me/notifications/:id/read",auth,async(req,res)=>{
  try{
    const r=await Notification.updateOne({_id:req.params.id,userId:req.auth.id},{$set:{read:true}});
    if(!r.matchedCount)return res.status(404).json({success:false,message:"Notification not found"});
    res.json({success:true});
  }catch(e){res.status(500).json({success:false,message:"Unable to mark notification as read"});}
});
app.post("/api/me/notifications/read-all",auth,async(req,res)=>{
  try{await Notification.updateMany({userId:req.auth.id,read:false},{$set:{read:true}});res.json({success:true});}
  catch(e){res.status(500).json({success:false,message:"Unable to mark notifications as read"});}
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
  if(!user)return res.status(404).json({success:false,message:"User not found"});
  const members=await User.find({referredBy:user.referralCode}).select("username email createdAt creditPoints");
  res.json({
    success:true,
    referralCode:user.referralCode||"",
    referralLink:"",
    referralBonus:Number(user.referralBonus||0),
    referralCount:members.length,
    bonusPerReferral:20,
    members
  });
});

app.get("/api/auth/validate-invite/:code",async(req,res)=>{
  try{
    const code=String(req.params.code||"").trim().toUpperCase();
    if(!code)return res.json({success:true,valid:false,message:"Invite code is required"});
    const adminInvite=await InviteCode.findOne({
      code,
      $or:[
        {active:true},
        {active:false,usedAt:{$ne:null}}
      ]
    }).select("code ownerAdminUsername useCount active");
    if(adminInvite){
      return res.json({
        success:true,valid:true,type:"admin",
        code:adminInvite.code,
        ownerAdminUsername:adminInvite.ownerAdminUsername||"",
        bonus:0,
        reusable:true,
        useCount:Number(adminInvite.useCount||0),
        message:"Valid platform invite code. This code can be used by multiple people until revoked."
      });
    }
    const referrer=await User.findOne({referralCode:code,role:"user"}).select("username referralCode");
    if(referrer){
      return res.json({
        success:true,valid:true,type:"user",
        code:referrer.referralCode,
        username:referrer.username,
        bonus:20,
        message:"Valid invite code. 20 bonus points will be added after registration."
      });
    }
    return res.json({success:true,valid:false,message:"Invalid or inactive invite code"});
  }catch(e){
    res.status(500).json({success:false,message:"Unable to validate invite code"});
  }
});

/* Admin */
app.get("/api/admin/announcements",auth,admin,async(req,res)=>{
  try{
    const rows=await Announcement.find().sort({createdAt:-1}).limit(100).lean();
    res.json({success:true,announcements:rows});
  }catch(e){res.status(500).json({success:false,message:"Unable to load announcements"});}
});
app.post("/api/admin/announcements",auth,admin,async(req,res)=>{
  try{
    const title=String(req.body?.title||"").trim().slice(0,120);
    const text=String(req.body?.text||"").trim().slice(0,5000);
    const image=String(req.body?.image||"").trim();
    const audience=String(req.body?.audience||"all");
    let recipientIds=[];
    if(audience==="selected"){
      recipientIds=[...new Set((Array.isArray(req.body?.recipientIds)?req.body.recipientIds:[]).map(x=>String(x).trim()).filter(x=>mongoose.isValidObjectId(x)))];
      if(!recipientIds.length)return res.status(400).json({success:false,message:"Select at least one user"});
      const count=await User.countDocuments({_id:{$in:recipientIds},role:"user"});
      if(count!==recipientIds.length)return res.status(400).json({success:false,message:"One or more selected users were not found"});
    }else if(audience!=="all")return res.status(400).json({success:false,message:"Invalid audience"});
    if(!title&&!text&&!image)return res.status(400).json({success:false,message:"Add a title, message or image"});
    if(image&&(!/^data:image\/(png|jpe?g|webp|gif);base64,/i.test(image)||image.length>1400000))
      return res.status(400).json({success:false,message:"Image must be PNG, JPG, WEBP or GIF and smaller than 1 MB"});
    const announcement=await Announcement.create({title,text,image,audience,recipientIds,createdBy:req.auth.username||"admin"});
    res.status(201).json({success:true,announcement});
  }catch(e){console.error("create announcement",e);res.status(500).json({success:false,message:"Unable to create announcement"});}
});
app.delete("/api/admin/announcements/:id",auth,admin,async(req,res)=>{
  try{
    const row=await Announcement.findByIdAndDelete(req.params.id);
    if(!row)return res.status(404).json({success:false,message:"Announcement not found"});
    res.json({success:true,deleted:true});
  }catch(e){res.status(500).json({success:false,message:"Unable to delete announcement"});}
});
app.get("/api/admin/activity",auth,admin,async(req,res)=>{
  try{
    const filter={};
    if(req.auth?.adminType!=="superadmin")filter.ownerAdminId=String(req.auth.id);
    const rows=await AdminActivity.find(filter).sort({createdAt:-1}).limit(200).lean();
    res.set("Cache-Control","no-store");
    res.json({success:true,activities:rows});
  }catch(e){console.error("admin activity",e);res.status(500).json({success:false,message:"Unable to load registration and login activity"});}
});
app.get("/api/admin/users",auth,admin,async(req,res)=>{
  const users=await User.find().sort({createdAt:-1}).lean();
  const safeUsers=users.map(({passwordHash,withdrawalPasswordHash,...user})=>user);
  res.json({success:true,users:safeUsers});
});
app.post("/api/admin/users/:id/vip",auth,admin,async(req,res)=>{
  const level=Number(req.body?.vipLevel);
  if(!Number.isInteger(level)||level<0||level>3)return res.status(400).json({success:false,message:"VIP level must be 0, 1, 2 or 3"});
  const user=await User.findByIdAndUpdate(req.params.id,{vipLevel:level},{new:true});
  if(!user)return res.status(404).json({success:false,message:"User not found"});
  await TaskProgress.deleteOne({userId:user._id});
  res.json({success:true,user:publicUser(user)});
});
app.get("/api/admin/transactions/:id/proof",auth,admin,async(req,res)=>{
  try{
    const t=await Transaction.findById(req.params.id).select("proofImage details type").lean();
    if(!t)return res.status(404).json({success:false,message:"Transaction not found"});
    const proofImage=String(t.proofImage||t.details?.proofImage||t.details?.screenshot||"");
    if(!proofImage)return res.status(404).json({success:false,message:"No payment screenshot was saved with this transaction. This record has no image to display."});
    if(!proofImage.startsWith("data:image/")&&!proofImage.startsWith("https://")&&!proofImage.startsWith("http://"))
      return res.status(422).json({success:false,message:"The saved payment screenshot has an unsupported format."});
    res.json({success:true,proofImage});
  }catch(e){
    console.error("load transaction proof",e);
    res.status(500).json({success:false,message:"Unable to load payment screenshot"});
  }
});
app.get("/api/admin/transactions",auth,admin,async(req,res)=>{
  res.json({success:true,transactions:await Transaction.find().sort({createdAt:-1})});
});
app.post("/api/admin/transactions/:id/approve",auth,admin,async(req,res)=>{
  try{
    const t=await Transaction.findById(req.params.id);
    if(!t)return res.status(404).json({success:false,message:"Transaction not found"});
    if(t.status!=="pending")return res.status(400).json({success:false,message:"Transaction already reviewed"});
    const user=await User.findById(t.userId);
    if(!user)return res.status(404).json({success:false,message:"User not found"});
    const requestedCurrency=String(t.currency||user.currency||"USDT").trim().toUpperCase();
    if(!SUPPORTED_CURRENCIES.includes(requestedCurrency))return res.status(400).json({success:false,message:"Unsupported transaction currency; balance was not changed"});
    const currency=requestedCurrency,w=walletMap(user),amount=Number(t.amount);
    if(!Number.isFinite(amount)||amount<=0)return res.status(400).json({success:false,message:"Invalid transaction amount; balance was not changed"});
    let creditedAmountUSDT=null;
    if(t.type==="deposit"){
      creditedAmountUSDT=Number((Number.isFinite(Number(t.convertedAmountUSDT))&&t.convertedAmountUSDT!==null
        ?Number(t.convertedAmountUSDT):convertCurrencyAmount(amount,currency,"USDT")).toFixed(2));
      if(!Number.isFinite(creditedAmountUSDT)||creditedAmountUSDT<=0)return res.status(400).json({success:false,message:"Invalid converted USDT amount; balance was not changed"});
      setWalletBalance(user,"USDT",Number(w.USDT||0)+creditedAmountUSDT);
      applyInsufficientBalanceCredit(user,creditedAmountUSDT);
      t.convertedAmountUSDT=creditedAmountUSDT;
    }
    if(t.type==="withdrawal" && !t.reserved){
      const debitUSDT=Number(convertCurrencyAmount(amount,currency,"USDT").toFixed(2));
      const available=Number(w.USDT||0);
      if(available<debitUSDT)return res.status(400).json({success:false,message:"Insufficient balance",currency,availableBalance:Number(convertCurrencyAmount(available,"USDT",currency).toFixed(2))});
      setWalletBalance(user,"USDT",Number((available-debitUSDT).toFixed(2)));
    }
    syncLegacyBalance(user);await user.save();
    t.status="approved";t.reviewedAt=new Date();t.note=String(req.body?.note||t.note||"");await t.save();
    try{await Notification.create({userId:user._id,type:t.type==="deposit"?"deposit_approved":"withdrawal_approved",title:t.type==="deposit"?"Deposit approved":"Withdrawal approved",text:t.type==="deposit"?"Your deposit has been accepted and credited to your USDT balance.":"Your withdrawal request has been approved.",metadata:{transactionId:String(t._id),amount:Number(t.amount||0),currency:String(t.currency||"USDT"),creditedUSDT:t.type==="deposit"?creditedAmountUSDT:undefined}});}catch(notificationError){console.error("approval notification failed",notificationError.message);}
    res.json({success:true,transaction:t,user:publicUser(user),creditedCurrency:t.type==="deposit"?"USDT":undefined,creditedAmount:t.type==="deposit"?creditedAmountUSDT:undefined});
  }catch(e){
    console.error("approve transaction",e);
    res.status(500).json({success:false,message:"Unable to approve transaction. Please refresh and check transaction status before retrying."});
  }
});
app.post("/api/admin/transactions/:id/reject",auth,admin,async(req,res)=>{
  const reason=String(req.body?.reason||"").trim();
  if(reason.length>1000)return res.status(400).json({success:false,message:"Rejection reason is too long"});
  const t=await Transaction.findById(req.params.id);
  if(!t)return res.status(404).json({success:false,message:"Transaction not found"});
  if(t.status!=="pending")return res.status(400).json({success:false,message:"Transaction already reviewed"});
  const user=await User.findById(t.userId);
  if(!user)return res.status(404).json({success:false,message:"User not found"});
  if(t.type==="withdrawal"&&t.reserved){
    const w=walletMap(user);
    const refundUSDT=Number(t.debitedAmount||convertCurrencyAmount(Number(t.amount||0),normCurrency(t.currency||user.currency),"USDT"));
    setWalletBalance(user,"USDT",Number((Number(w.USDT||0)+refundUSDT).toFixed(2)));
    syncLegacyBalance(user);await user.save();
  }
  t.status="rejected";t.rejectionReason=reason;t.note=reason;t.reviewedAt=new Date();await t.save();
  try{await Notification.create({userId:user._id,type:t.type==="withdrawal"?"withdrawal_rejected":"deposit_rejected",title:t.type==="withdrawal"?"Withdrawal rejected":"Deposit rejected",text:reason||"Your transaction request was rejected by Admin.",metadata:{transactionId:String(t._id),amount:Number(t.amount||0),currency:String(t.currency||"USDT"),reason}});}catch(notificationError){console.error("rejection notification failed",notificationError.message);}
  res.json({success:true,transaction:t,user:publicUser(user)});
});
app.get("/api/me/lucky-spin/tickets",auth,async(req,res)=>{try{const user=await User.findById(req.auth.id).select("spinTickets");if(!user)return res.status(404).json({success:false,message:"User not found"});res.set("Cache-Control","no-store");res.json({success:true,freeTickets:Number(user.spinTickets||0)})}catch(e){res.status(500).json({success:false,message:"Unable to load spin tickets"})}});

app.post("/api/me/lucky-spin/spin",auth,async(req,res)=>{try{
 const user=await User.findOneAndUpdate({_id:req.auth.id,role:"user",spinTickets:{$gt:0}},{$inc:{spinTickets:-1}},{new:true});
 if(!user)return res.status(400).json({success:false,message:"You do not have any free spin tickets"});
 const prizes=[
  {id:"no_reward",label:"No Rewards",amount:0,weight:79},
  {id:"usd10",label:"$10",amount:10,weight:12},
  {id:"usd50",label:"$50",amount:50,weight:6},
  {id:"usd1000",label:"$1,000",amount:1000,weight:1},
  {id:"iphone18promax",label:"iPhone 18 Pro Max",amount:0,weight:1},
  {id:"five_tickets",label:"5 Tickets",amount:0,weight:1}
 ];
 const mode=["random","no_reward","usd10","usd50","usd1000","iphone18promax","five_tickets"].includes(user.luckySpinMode)?user.luckySpinMode:"random";
 let prize;
 if(mode==="random"){const total=prizes.reduce((n,p)=>n+p.weight,0);let pick=Math.random()*total;prize=prizes.find(p=>(pick-=p.weight)<=0)||prizes[0];}
 else prize=prizes.find(p=>p.id===mode)||prizes[0];
 let creditedUSDT=0;
 if(prize.amount>0){const balances=walletMap(user),before=Number(balances.USDT||0);creditedUSDT=Number(prize.amount.toFixed(2));setWalletBalance(user,"USDT",Number((before+creditedUSDT).toFixed(2)));}
 if(prize.id==="five_tickets")user.spinTickets=Number(user.spinTickets||0)+5;
 const spinId=new mongoose.Types.ObjectId().toString();
 user.spinHistory=user.spinHistory||[];
 user.spinHistory.unshift({spinId,prizeId:prize.id,label:prize.label,amount:Number(prize.amount||0),creditedUSDT,claimStatus:"unclaimed",createdAt:new Date()});
 await Notification.create({userId:user._id,type:"lucky_spin",title:"Lucky Spin result",text:"You received: "+prize.label+(creditedUSDT>0?" ("+creditedUSDT.toFixed(2)+" USDT credited)":"."),metadata:{spinId,prizeId:prize.id,label:prize.label,creditedUSDT}});
 if(user.spinHistory.length>200)user.spinHistory=user.spinHistory.slice(0,200);
 syncLegacyBalance(user);await user.save();
 try{await Notification.create({userId:user._id,type:"lucky_spin",title:"Lucky Spin result",text:"You received: "+prize.label+(creditedUSDT>0?" ("+creditedUSDT.toFixed(2)+" USDT credited)":""),metadata:{spinId,prizeId:prize.id,label:prize.label,creditedUSDT}});}catch(notificationError){console.error("Lucky Spin notification failed",notificationError.message);}
 res.set("Cache-Control","no-store");
 return res.json({success:true,spinId,prize:{id:prize.id,label:prize.label,amount:prize.amount},creditedUSDT,freeTickets:Number(user.spinTickets||0),claimStatus:"unclaimed",user:publicUser(user)});
 }catch(e){console.error("Lucky Spin draw failed",e);res.status(500).json({success:false,message:"Unable to complete spin"})}});

app.get("/api/me/lucky-spin/history",auth,async(req,res)=>{try{const user=await User.findById(req.auth.id).select("spinHistory");if(!user)return res.status(404).json({success:false,message:"User not found"});res.set("Cache-Control","no-store");res.json({success:true,history:(user.spinHistory||[]).slice().sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt)).map(x=>({spinId:x.spinId,prizeId:x.prizeId,label:x.label,amount:Number(x.amount||0),creditedUSDT:Number(x.creditedUSDT||0),claimStatus:x.claimStatus||"unclaimed",createdAt:x.createdAt,claimedAt:x.claimedAt||null}))})}catch(e){console.error("Lucky Spin history",e);res.status(500).json({success:false,message:"Unable to load spin history"})}});
app.post("/api/me/lucky-spin/:spinId/claim",auth,async(req,res)=>{try{const user=await User.findById(req.auth.id);if(!user)return res.status(404).json({success:false,message:"User not found"});const item=(user.spinHistory||[]).find(x=>x.spinId===req.params.spinId);if(!item)return res.status(404).json({success:false,message:"Spin result not found"});if(item.claimStatus!=="claimed"){item.claimStatus="claimed";item.claimedAt=new Date();await user.save();}res.json({success:true,spinId:item.spinId,prizeId:item.prizeId,claimStatus:item.claimStatus,claimedAt:item.claimedAt})}catch(e){console.error("Lucky Spin claim",e);res.status(500).json({success:false,message:"Unable to claim spin result"})}});

app.post("/api/admin/users/:id/lucky-spin/setting",auth,admin,async(req,res)=>{try{
 if(!mongoose.isValidObjectId(req.params.id))return res.status(400).json({success:false,message:"Invalid user id"});
 const mode=String(req.body?.mode||"");
 const allowed=["random","no_reward","usd10","usd50","usd1000","iphone18promax","five_tickets"];
 if(!allowed.includes(mode))return res.status(400).json({success:false,message:"Invalid wheel setting"});
 const user=await User.findOneAndUpdate({_id:req.params.id,role:"user"},{$set:{luckySpinMode:mode}},{new:true});
 if(!user)return res.status(404).json({success:false,message:"User not found"});
 res.json({success:true,userId:String(user._id),username:user.username,mode:user.luckySpinMode});
 }catch(e){console.error("Admin Lucky Spin setting",e);res.status(500).json({success:false,message:"Unable to save wheel setting"})}});
app.post("/api/admin/users/:id/lucky-spin/tickets",auth,admin,async(req,res)=>{try{if(!mongoose.isValidObjectId(req.params.id))return res.status(400).json({success:false,message:"Invalid user id"});const delta=Number(req.body?.delta);if(!Number.isInteger(delta)||delta===0||Math.abs(delta)>10000)return res.status(400).json({success:false,message:"Ticket adjustment must be a non-zero whole number between -10000 and 10000"});const user=await User.findOneAndUpdate({_id:req.params.id,role:"user",$expr:{$gte:[{$ifNull:["$spinTickets",0]},Math.max(0,-delta)]}},{$inc:{spinTickets:delta}},{new:true});if(!user){const exists=await User.exists({_id:req.params.id,role:"user"});if(!exists)return res.status(404).json({success:false,message:"User not found"});return res.status(400).json({success:false,message:"Ticket balance would become negative"});}res.json({success:true,userId:String(user._id),username:user.username,freeTickets:Number(user.spinTickets||0),message:"Lucky Spin tickets updated"})}catch(e){console.error("Admin ticket adjustment",e);res.status(500).json({success:false,message:"Unable to update spin tickets"})}});

app.get("/api/admin/users/:id/insufficient-balance",auth,admin,async(req,res)=>{
  const user=await User.findById(req.params.id);
  if(!user)return res.status(404).json({success:false,message:"User not found"});
  res.json({success:true,rule:{enabled:Boolean(user.insufficientBalanceEnabled),taskNumber:Number(user.insufficientBalanceTaskNumber||0),requiredAmount:Number(user.insufficientBalanceRequiredAmount||0),remainingAmount:Number(user.insufficientBalanceRemainingAmount ?? user.insufficientBalanceRequiredAmount ?? 0),commissionMultiplier:Number(user.insufficientBalanceCommissionMultiplier||1)}});
});
app.post("/api/admin/users/:id/insufficient-balance",auth,admin,async(req,res)=>{
  const enabled=req.body?.enabled===true || String(req.body?.enabled).toLowerCase()==="true";
  const taskNumber=Number(req.body?.taskNumber||0),requiredAmount=Number(req.body?.requiredAmount||0),commissionMultiplier=Number(req.body?.commissionMultiplier||1);
  if(enabled&&(!Number.isInteger(taskNumber)||taskNumber<1||taskNumber>5))return res.status(400).json({success:false,message:"Task number must be between 1 and 5"});
  if(enabled&&(!Number.isFinite(requiredAmount)||requiredAmount<=0))return res.status(400).json({success:false,message:"Required amount must be greater than 0"});
  if(enabled&&(!Number.isFinite(commissionMultiplier)||commissionMultiplier<1||commissionMultiplier>20))return res.status(400).json({success:false,message:"Commission multiplier must be between 1 and 20x"});
  const user=await User.findByIdAndUpdate(req.params.id,{$set:{insufficientBalanceEnabled:enabled,insufficientBalanceTaskNumber:enabled?taskNumber:0,insufficientBalanceRequiredAmount:enabled?Number(requiredAmount.toFixed(2)):0,insufficientBalanceRemainingAmount:enabled?Number(requiredAmount.toFixed(2)):0,insufficientBalanceCommissionMultiplier:enabled?commissionMultiplier:1}},{new:true,runValidators:true});
  if(!user)return res.status(404).json({success:false,message:"User not found"});
  res.json({success:true,rule:{enabled:Boolean(user.insufficientBalanceEnabled),taskNumber:Number(user.insufficientBalanceTaskNumber||0),requiredAmount:Number(user.insufficientBalanceRequiredAmount||0),remainingAmount:Number(user.insufficientBalanceRemainingAmount||0),commissionMultiplier:Number(user.insufficientBalanceCommissionMultiplier||1)},user:publicUser(user)});
});

app.post("/api/admin/users/:id/reset-withdrawal-password",auth,admin,async(req,res)=>{
  try{
    if(!mongoose.isValidObjectId(req.params.id))return res.status(400).json({success:false,message:"Invalid user id"});
    const newPassword=String(req.body?.newPassword||"");
    if(newPassword.length<6||newPassword.length>128)return res.status(400).json({success:false,message:"Withdrawal password must be 6 to 128 characters"});
    const user=await User.findById(req.params.id).select("+withdrawalPasswordHash");
    if(!user||user.role!=="user")return res.status(404).json({success:false,message:"Platform user not found"});
    user.withdrawalPasswordHash=hashPassword(newPassword);
    await user.save();
    const saved=await User.findById(user._id).select("+withdrawalPasswordHash role");
    if(!saved||saved.role!=="user"||!verifyPassword(newPassword,saved.withdrawalPasswordHash))return res.status(500).json({success:false,message:"Withdrawal password reset could not be verified"});
    console.log("Admin reset withdrawal password for user",String(user._id));
    res.json({success:true,passwordChanged:true,message:"User withdrawal password reset successfully"});
  }catch(e){console.error("Admin reset user withdrawal password",e);res.status(500).json({success:false,message:"Unable to reset withdrawal password"});}
});
app.put("/api/admin/users/:id/bank-accounts",auth,admin,async(req,res)=>{
  try{
    if(!mongoose.isValidObjectId(req.params.id))return res.status(400).json({success:false,message:"Invalid user id"});
    if(!Array.isArray(req.body?.bankAccounts)||req.body.bankAccounts.length>20)return res.status(400).json({success:false,message:"Bank accounts must be a list of up to 20 accounts"});
    const bankAccounts=[];
    for(const item of req.body.bankAccounts){
      const bankName=String(item?.bankName||"").trim(),accountName=String(item?.accountName||"").trim(),accountNumber=String(item?.accountNumber||"").trim(),additionalDetails=String(item?.additionalDetails||"").trim();
      if(!bankName||!accountName||!accountNumber)return res.status(400).json({success:false,message:"Bank name, account name and account number are required"});
      if(bankName.length>120||accountName.length>120||accountNumber.length>160||additionalDetails.length>1000)return res.status(400).json({success:false,message:"Bank account information is too long"});
      const entry={bankName,accountName,accountNumber,additionalDetails};
      if(item._id&&mongoose.isValidObjectId(item._id))entry._id=item._id;
      if(item.createdAt&&Number.isFinite(new Date(item.createdAt).getTime()))entry.createdAt=new Date(item.createdAt);
      bankAccounts.push(entry);
    }
    const user=await User.findById(req.params.id);
    if(!user||user.role!=="user")return res.status(404).json({success:false,message:"Platform user not found"});
    user.bankAccounts=bankAccounts;await user.save();
    const saved=await User.findById(user._id).select("bankAccounts");
    res.json({success:true,message:"User bank information updated",bankAccounts:(saved.bankAccounts||[]).map(a=>({id:a._id,bankName:a.bankName,accountName:a.accountName,accountNumber:a.accountNumber,additionalDetails:a.additionalDetails||"",createdAt:a.createdAt}))});
  }catch(e){console.error("Admin update user bank accounts",e);res.status(500).json({success:false,message:"Unable to update bank information"});}
});
app.post("/api/admin/users/:id/reset-password",auth,admin,async(req,res)=>{
  try{
    if(!mongoose.isValidObjectId(req.params.id))
      return res.status(400).json({success:false,message:"Invalid user id"});
    const newPassword=String(req.body?.newPassword||"");
    if(newPassword.length<8)
      return res.status(400).json({success:false,message:"New password must be at least 8 characters"});
    if(newPassword.length>128)
      return res.status(400).json({success:false,message:"New password is too long"});
    const user=await User.findById(req.params.id);
    if(!user || user.role!=="user")
      return res.status(404).json({success:false,message:"Platform user not found"});
    user.passwordHash=hashPassword(newPassword);
    await user.save();
    const saved=await User.findById(user._id).select("passwordHash role");
    if(!saved || saved.role!=="user" || !verifyPassword(newPassword,saved.passwordHash))
      return res.status(500).json({success:false,message:"Password reset could not be verified"});
    console.log("Admin reset login password for user",String(user._id));
    res.json({success:true,passwordChanged:true,message:"User login password reset successfully"});
  }catch(e){
    console.error("Admin reset user password",e);
    res.status(500).json({success:false,message:"Unable to reset user password"});
  }
});
app.get("/api/admin/users/:id/balances",auth,admin,async(req,res)=>{
  const user=await User.findById(req.params.id);if(!user)return res.status(404).json({success:false,message:"User not found"});
  res.json({success:true,balances:walletMap(user)}); 
});
app.post("/api/admin/users/:id/balance",auth,admin,async(req,res)=>{
  // Accept both "amount" and the admin UI's legacy "delta" field.
  // This keeps older admin clients working while making currency-specific
  // balance updates reliable.
  const rawAmount=req.body?.amount ?? req.body?.delta;
  const amount=Number(rawAmount);
  const currency=normCurrency(req.body?.currency);
  if(!Number.isFinite(amount)||amount===0)return res.status(400).json({success:false,message:"Enter a non-zero balance change"});
  const user=await User.findById(req.params.id);
  if(!user)return res.status(404).json({success:false,message:"User not found"});
  const w=walletMap(user);
  const current=Number(w.USDT||0);
  const deltaUSDT=Number(convertCurrencyAmount(amount,currency,"USDT").toFixed(2));
  const next=Number((current+deltaUSDT).toFixed(2));
  if(next<0)return res.status(400).json({success:false,message:"Balance cannot be negative",currency:"USDT",currentBalance:current});
  setWalletBalance(user,"USDT",next);
  if(deltaUSDT>0) applyInsufficientBalanceCredit(user,deltaUSDT);
  syncLegacyBalance(user);
  await user.save();
  const fresh=await User.findById(user._id);
  res.json({
    success:true,
    user:publicUser(fresh),
    currency:"USDT",
    amount:deltaUSDT,
    previousBalance:current,
    newBalance:Number(walletMap(fresh).USDT||0),
    balances:{USDT:Number(walletMap(fresh).USDT||0)}
  });
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
app.patch("/api/admin/products/:id",auth,admin,async(req,res)=>{
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

async function ensureProductCatalog(){
  const catalogNames=["Premium Stainless Steel Screw Set","CAT6 Flat Patch Cord","Aluminum Fountain Pen","Waterproof Self Adhesive Wallpaper","Smart Home Accessory","Cordless Power Drill","Rechargeable LED Work Light","USB-C Fast Charging Cable","Wireless Mouse","Mechanical Keyboard","Laptop Stand","Phone Holder","Bluetooth Speaker","Smart LED Bulb","Portable Power Bank","Digital Kitchen Scale","Stainless Steel Water Bottle","Non Slip Floor Mat","Microfiber Cleaning Cloth","Storage Organizer Box","Desk Lamp","Notebook Set","Ballpoint Pen Set","A4 Document Folder","Adhesive Tape Set","Precision Screwdriver Kit","Measuring Tape","Mini Hand Tool Set","Safety Work Gloves","Protective Face Shield","Cable Management Clips","HDMI Cable","USB Hub","Ethernet Network Adapter","Wireless Door Sensor","Smart Plug","Motion Sensor Light","Desk Organizer","Travel Adapter","Phone Charging Stand","Tablet Stand","Computer Webcam","Mini Tripod","Reusable Shopping Bag","Kitchen Storage Container","Silicone Spatula Set","Non Stick Pan","Coffee Mug Set","Kitchen Knife Organizer","Bathroom Storage Rack","Laundry Storage Bag","Foldable Storage Basket","Home Decoration Frame","Curtain Tieback Set","Wall Hook Set","Furniture Handle Set","Door Stopper Set","Garden Hand Tool Set","Plant Watering Bottle","LED String Light","Outdoor Utility Rope","Compact Tool Box","Multi Purpose Cleaning Brush","Reusable Food Cover Set","Portable Sewing Kit","Travel Toiletry Organizer","Document Storage Case","Cable Tester","Mini Digital Thermometer","Rechargeable Flashlight","Magnetic Tool Holder"];
  const existing=await Product.find({name:{$in:catalogNames}}).select("name"),have=new Set(existing.map(p=>p.name));
  const images=catalogNames.map(name=>"https://picsum.photos/seed/"+encodeURIComponent(name)+"/900/600");
  const add=catalogNames.filter(n=>!have.has(n)).map((name,i)=>({
    name,description:"Marketplace product review task item.",category:"General",price:0,
    profitRate:8+(i%6),image:images[i%images.length],requiredVip:1,active:true,
    valueTier:1+(i%5)
  }));
  if(add.length)await Product.insertMany(add);
  // Give every seeded catalog product its own stable image so the full catalog
  // does not reuse the same five pictures.
  const catalogProducts=await Product.find({name:{$in:catalogNames}});
  for(const p of catalogProducts){
    const expected="https://picsum.photos/seed/"+encodeURIComponent(p.name)+"/900/600";
    if(!p.image || !String(p.image).includes("picsum.photos")){
      p.image=expected;
      await p.save();
    }
  }
  const missingTier=await Product.find({name:{$in:catalogNames},$or:[{valueTier:{$exists:false}},{valueTier:{$lt:1}},{valueTier:{$gt:5}}]});
  for(const p of missingTier){
    const idx=catalogNames.indexOf(p.name);
    p.valueTier=idx>=0?1+(idx%5):3;
    await p.save();
  }
}

async function start(){
  if(!MONGO_URL)throw new Error("MONGO_URL is not configured");
  await mongoose.connect(MONGO_URL);
  // Do not rewrite existing user balances during server startup. User balances
  // must remain unchanged; wallet normalization requires an explicit, audited recovery.
  await ensureProductCatalog();
  console.log("MongoDB connected successfully");
  app.listen(PORT,()=>console.log(`Zonguru backend running on port ${PORT}`));
}
start().catch(e=>{
  console.error("Startup error:",e);
  process.exit(1);
});
