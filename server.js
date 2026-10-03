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
    currency:user.currency, balances:user.balances||{}, totalProfit:user.totalProfit,
    referralCode:user.referralCode, referredBy:user.referredBy||null,
    frozenAmount:Number(user.frozenAmount||0),
    creditPoints:Number(user.creditPoints||0),
    referralBonus:Number(user.referralBonus||0),
    creditScore:Number(user.creditScore??100),
    vipLevel:Number(user.vipLevel||0),
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
  insufficientBalanceCommissionMultiplier:{type:Number,default:1,min:1,max:20},
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
  method:String,details:Object,status:{type:String,default:"pending"},
  note:String,rejectionReason:{type:String,default:""},
  reserved:{type:Boolean,default:false},
  createdAt:{type:Date,default:Date.now},reviewedAt:Date
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
    res.json({success:true,message:"Registration successful",token:signUser(user),user:publicUser(user)});
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

const SUPPORTED_CURRENCIES=["USDT","USD","MXN","EUR","GBP","CAD","AUD","JPY","CNY","SGD","THB","MYR","BRL","INR","EGP"];
function normCurrency(v){const x=String(v||"USDT").trim().toUpperCase();return SUPPORTED_CURRENCIES.includes(x)?x:"USDT";}
function walletMap(user){
  const raw=(user.balances&&typeof user.balances==="object"&&!Array.isArray(user.balances))?user.balances:{};
  const out={};
  for(const k of Object.keys(raw||{})){const n=Number(raw[k]);if(Number.isFinite(n))out[normCurrency(k)]=Number(n.toFixed(2));}
  const cur=normCurrency(user.currency);
  if(!Number.isFinite(out[cur]))out[cur]=Number(user.balance||0);
  else if(Number(user.balance||0)!==0 && Object.keys(out).length===1)out[cur]=Number(user.balance||0);
  return out;
}
function setWalletBalance(user,currency,amount){
  const cur=normCurrency(currency),w=walletMap(user);
  const n=Number(amount);
  if(!Number.isFinite(n)||n<0)throw new Error("Invalid balance amount");
  w[cur]=Number(n.toFixed(2));user.balances=w;
  if(normCurrency(user.currency)===cur)user.balance=w[cur];
}
function syncLegacyBalance(user){
  const cur=normCurrency(user.currency),w=walletMap(user);
  user.balances=w;user.balance=Number(w[cur]||0);
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
    const currency=String(req.body?.currency ?? user.currency ?? "USDT").trim().toUpperCase();
    const allowedCurrencies=["USDT","MXN","USD","EUR","GBP","CAD","AUD","JPY","CNY","SGD","THB","MYR","BRL","INR","EGP"];
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
    const shortfall=userRuleTriggered?Number(user.insufficientBalanceRequiredAmount||0):0;
    const balance=Number(user.balance||0);

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
      const desiredAmount=Math.round((balance+shortfall)*100)/100;
      if(Math.abs(Number(task.currentProductAmount||0)-desiredAmount)>0.009){
        task.currentProductAmount=desiredAmount;
        task.currentTaskNumber=taskNumber;
        task.updatedAt=new Date();
        await task.save();
      }
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
        amount=Math.round((balance+shortfall)*100)/100;
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
    const specialTriggered=userRuleTriggered,configuredShortfall=userRuleTriggered?Number(user.insufficientBalanceRequiredAmount||0):0;
    const requiredBalance=userRuleTriggered?amount:(product.balanceGuardEnabled?amount:0);
    if(requiredBalance>0&&Number(user.balance||0)<requiredBalance){
      const availableBalance=Number(user.balance||0),difference=Math.max(0,requiredBalance-availableBalance);
      let pending=await Order.findOne({userId:user._id,productId:product._id,taskNumber,status:"pending"}).sort({createdAt:-1});
      if(!pending)pending=await Order.create({userId:user._id,productId:product._id,productName:product.name||"Product",amount,profitRate:rate,commission:0,baseCommission:amount*(rate/100),commissionMultiplier:1,availableBalance,shortfall:difference,taskNumber,reviewText:String(req.body?.reviewText||"").trim(),status:"pending"});
      return res.status(400).json({success:false,insufficientBalance:true,orderStatus:"pending",orderId:pending._id,specialTask:specialTriggered,message:"Insufficient balance. Please contact Customer Service.",orderAmount:amount,availableBalance,difference,shortfall:configuredShortfall||difference,taskNumber});
    }
    const reviewText=String(req.body?.reviewText||"").trim();
    if(reviewText.length>1000)return res.status(400).json({success:false,message:"Review is too long"});
    const baseCommission=amount*(rate/100),commissionMultiplier=specialTriggered?Math.max(1,Math.min(20,Number(user.insufficientBalanceCommissionMultiplier||1))):1,commission=baseCommission*commissionMultiplier;
    task.completedIds.push(req.params.productId);task.productIds=[...(task.productIds||[]),req.params.productId].slice(-20);task.recentProductIds=[...(task.recentProductIds||[]),req.params.productId].slice(-15);task.currentProductId=null;task.currentProductAmount=0;task.currentTaskNumber=0;task.updatedAt=new Date();await task.save();
    await Order.create({userId:req.auth.id,productId:req.params.productId,productName:product.name||"Product",amount,profitRate:rate,commission,baseCommission,commissionMultiplier,availableBalance:Number(user.balance||0),shortfall:0,taskNumber,reviewText,status:"completed"});
    const updatedUser=await User.findOneAndUpdate({_id:user._id},{$inc:{balance:commission,totalProfit:commission}},{new:true,runValidators:false});
    if(!updatedUser)throw new Error("Unable to update account balance");
    const completed=task.completedIds.length;
    res.json({success:true,completed,total:5,taskComplete:completed>=5,commission,creditedBalance:Number(updatedUser.balance||0),totalProfit:Number(updatedUser.totalProfit||0),message:"Order completed successfully"});
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
  const amount=Number(req.body?.amount||0),currency=normCurrency(req.body?.currency);
  if(!Number.isFinite(amount)||amount<=0)return res.status(400).json({success:false,message:"Invalid amount"});
  const t=await Transaction.create({userId:req.auth.id,type:"deposit",amount,currency,method:String(req.body?.method||""),details:req.body?.details||{},note:String(req.body?.note||""),status:"pending",reserved:false});
  res.json({success:true,transaction:t});
});

app.post("/api/withdrawals",auth,async(req,res)=>{
  const amount=Number(req.body?.amount||0),currency=normCurrency(req.body?.currency);
  const user=await User.findById(req.auth.id);
  if(!Number.isFinite(amount)||amount<=0)return res.status(400).json({success:false,message:"Invalid amount"});
  if(!user)return res.status(404).json({success:false,message:"User not found"});
  const w=walletMap(user);
  // Legacy accounts may have the selected-currency amount in user.balance
  // while balances[code] is still missing/stale. Treat that amount as the
  // selected wallet balance so valid withdrawals are not rejected.
  let available=Number(w[currency]||0);
  if(normCurrency(user.currency)===currency){
    const legacy=Number(user.balance||0);
    if(Number.isFinite(legacy) && legacy>available) available=legacy;
  }
  if(available<amount)return res.status(400).json({success:false,message:"Insufficient balance",currency,availableBalance:available,balances:w,accountCurrency:normCurrency(user.currency)});
  w[currency]=Number((available-amount).toFixed(2));
  user.balances=w;
  if(normCurrency(user.currency)===currency)user.balance=w[currency];
  await user.save();
  const t=await Transaction.create({userId:req.auth.id,type:"withdrawal",amount,currency,method:String(req.body?.method||""),details:req.body?.details||{},note:String(req.body?.note||""),status:"pending",reserved:true});
  res.json({success:true,transaction:t,user:publicUser(user)});
});

app.get("/api/orders",auth,async(req,res)=>{
  try{
    const orders=await Order.find({userId:req.auth.id}).sort({createdAt:-1});
    res.json({success:true,orders});
  }catch(e){res.status(500).json({success:false,message:"Unable to load order history"});}
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
app.get("/api/admin/users",auth,admin,async(req,res)=>{
  res.json({success:true,users:await User.find().sort({createdAt:-1})});
});
app.post("/api/admin/users/:id/vip",auth,admin,async(req,res)=>{
  const level=Number(req.body?.vipLevel);
  if(!Number.isInteger(level)||level<0||level>3)return res.status(400).json({success:false,message:"VIP level must be 0, 1, 2 or 3"});
  const user=await User.findByIdAndUpdate(req.params.id,{vipLevel:level},{new:true});
  if(!user)return res.status(404).json({success:false,message:"User not found"});
  await TaskProgress.deleteOne({userId:user._id});
  res.json({success:true,user:publicUser(user)});
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
  const currency=normCurrency(t.currency||user.currency),w=walletMap(user);
  if(t.type==="deposit")setWalletBalance(user,currency,Number(w[currency]||0)+Number(t.amount||0));
  if(t.type==="withdrawal" && !t.reserved){
    const available=Number(w[currency]||0);
    if(available<Number(t.amount||0))return res.status(400).json({success:false,message:"Insufficient balance",currency,availableBalance:available});
    setWalletBalance(user,currency,available-Number(t.amount||0));
  }
  syncLegacyBalance(user);await user.save();
  t.status="approved";t.reviewedAt=new Date();t.note=String(req.body?.note||t.note||"");await t.save();
  res.json({success:true,transaction:t,user:publicUser(user)});
});
app.post("/api/admin/transactions/:id/reject",auth,admin,async(req,res)=>{
  const reason=String(req.body?.reason||"").trim();
  if(reason.length>1000)return res.status(400).json({success:false,message:"Rejection reason is too long"});
  const t=await Transaction.findById(req.params.id);
  if(!t)return res.status(404).json({success:false,message:"Transaction not found"});
  if(t.status!=="pending")return res.status(400).json({success:false,message:"Transaction already reviewed"});
  const user=await User.findById(t.userId);
  if(!user)return res.status(404).json({success:false,message:"User not found"});
  const currency=normCurrency(t.currency||user.currency);
  if(t.type==="withdrawal"&&t.reserved){
    const w=walletMap(user);setWalletBalance(user,currency,Number(w[currency]||0)+Number(t.amount||0));syncLegacyBalance(user);await user.save();
  }
  t.status="rejected";t.rejectionReason=reason;t.note=reason;t.reviewedAt=new Date();await t.save();
  res.json({success:true,transaction:t,user:publicUser(user)});
});
app.get("/api/admin/users/:id/balances",auth,admin,async(req,res)=>{
  const user=await User.findById(req.params.id);if(!user)return res.status(404).json({success:false,message:"User not found"});
  res.json({success:true,balances:walletMap(user)}); 
});
app.post("/api/admin/users/:id/balance",auth,admin,async(req,res)=>{
  const amount=Number(req.body?.amount);
  const currency=normCurrency(req.body?.currency);
  if(!Number.isFinite(amount)||amount===0)return res.status(400).json({success:false,message:"Enter a non-zero balance change"});
  const user=await User.findById(req.params.id);
  if(!user)return res.status(404).json({success:false,message:"User not found"});
  const w=walletMap(user),next=Number((Number(w[currency]||0)+amount).toFixed(2));
  if(next<0)return res.status(400).json({success:false,message:"Balance cannot be negative",currency,currentBalance:Number(w[currency]||0)});
  setWalletBalance(user,currency,next);syncLegacyBalance(user);await user.save();
  res.json({success:true,user:publicUser(user),currency,amount:Number(amount.toFixed(2)),newBalance:next});
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
  await ensureProductCatalog();
  console.log("MongoDB connected successfully");
  app.listen(PORT,()=>console.log(`Zonguru backend running on port ${PORT}`));
}
start().catch(e=>{
  console.error("Startup error:",e);
  process.exit(1);
});
