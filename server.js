require("dotenv").config();

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");

const app = express();

app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;

const JWT_SECRET = process.env.JWT_SECRET;

const MONGODB_URI = process.env.MONGODB_URI;

if (!JWT_SECRET) {
  console.error("ERROR: JWT_SECRET is missing");
  process.exit(1);
}

if (!MONGODB_URI) {
  console.error("ERROR: MONGODB_URI is missing");
  process.exit(1);
}

/* =========================
   USER MODEL
========================= */

const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true,
      trim: true
    },

    passwordHash: {
      type: String,
      required: true
    },

    role: {
      type: String,
      enum: ["user", "admin"],
      default: "user"
    },

    balance: {
      type: Number,
      default: 0
    },

    currency: {
      type: String,
      default: "USDT"
    }
  },
  {
    timestamps: true
  }
);

const User = mongoose.model("User", userSchema);

/* =========================
   JWT
========================= */

function createToken(user) {
  return jwt.sign(
    {
      id: user._id.toString(),
      username: user.username,
      role: user.role
    },
    JWT_SECRET,
    {
      expiresIn: "7d"
    }
  );
}

/* =========================
   AUTH MIDDLEWARE
========================= */

function auth(req, res, next) {
  const header = req.headers.authorization;

  if (!header || !header.startsWith("Bearer ")) {
    return res.status(401).json({
      success: false,
      message: "Login required"
    });
  }

  const token = header.substring(7);

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    req.user = decoded;

    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Invalid or expired token"
    });
  }
}

/* =========================
   ADMIN MIDDLEWARE
========================= */

function adminOnly(req, res, next) {
  if (!req.user || req.user.role !== "admin") {
    return res.status(403).json({
      success: false,
      message: "Admin access required"
    });
  }

  next();
}

/* =========================
   HEALTH CHECK
========================= */

app.get("/", (req, res) => {
  res.json({
    success: true,
    service: "Zonguru Backend",
    status: "online"
  });
});

/* =========================
   REGISTER
========================= */

app.post("/api/auth/register", async (req, res) => {
  try {
    const username = String(req.body.username || "")
      .trim()
      .toLowerCase();

    const password = String(req.body.password || "");

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: "Username and password are required"
      });
    }

    if (username.length < 3) {
      return res.status(400).json({
        success: false,
        message: "Username must contain at least 3 characters"
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: "Password must contain at least 6 characters"
      });
    }

    const existingUser = await User.findOne({
      username
    });

    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: "Username already registered"
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const user = await User.create({
      username,
      passwordHash,
      role: "user",
      balance: 0,
      currency: "USDT"
    });

    const token = createToken(user);

    return res.status(201).json({
      success: true,
      message: "Registration successful",
      token,
      user: {
        id: user._id,
        username: user.username,
        role: user.role,
        balance: user.balance,
        currency: user.currency
      }
    });
  } catch (error) {
    console.error("REGISTER ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Registration failed"
    });
  }
});

/* =========================
   LOGIN
========================= */

app.post("/api/auth/login", async (req, res) => {
  try {
    const username = String(req.body.username || "")
      .trim()
      .toLowerCase();

    const password = String(req.body.password || "");

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: "Username and password are required"
      });
    }

    const user = await User.findOne({
      username
    });

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Invalid username or password"
      });
    }

    const validPassword = await bcrypt.compare(
      password,
      user.passwordHash
    );

    if (!validPassword) {
      return res.status(401).json({
        success: false,
        message: "Invalid username or password"
      });
    }

    const token = createToken(user);

    return res.json({
      success: true,
      message: "Login successful",
      token,
      user: {
        id: user._id,
        username: user.username,
        role: user.role,
        balance: user.balance,
        currency: user.currency
      }
    });
  } catch (error) {
    console.error("LOGIN ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Login failed"
    });
  }
});

/* =========================
   CURRENT USER
========================= */

app.get("/api/me", auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select(
      "-passwordHash"
    );

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found"
      });
    }

    return res.json({
      success: true,
      user: {
        id: user._id,
        username: user.username,
        role: user.role,
        balance: user.balance,
        currency: user.currency
      }
    });
  } catch (error) {
    console.error("ME ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Could not load user"
    });
  }
});

/* =========================
   ADMIN - USERS
========================= */

app.get(
  "/api/admin/users",
  auth,
  adminOnly,
  async (req, res) => {
    try {
      const users = await User.find()
        .select("-passwordHash")
        .sort({ createdAt: -1 });

      return res.json({
        success: true,
        users
      });
    } catch (error) {
      console.error("ADMIN USERS ERROR:", error);

      return res.status(500).json({
        success: false,
        message: "Could not load users"
      });
    }
  }
);

/* =========================
   ADMIN - UPDATE BALANCE
========================= */

app.post(
  "/api/admin/users/:id/balance",
  auth,
  adminOnly,
  async (req, res) => {
    try {
      const amount = Number(req.body.amount);

      if (!Number.isFinite(amount)) {
        return res.status(400).json({
          success: false,
          message: "Invalid amount"
        });
      }

      const user = await User.findById(
        req.params.id
      );

      if (!user) {
        return res.status(404).json({
          success: false,
          message: "User not found"
        });
      }

      user.balance = amount;

      await user.save();

      return res.json({
        success: true,
        message: "Balance updated",
        balance: user.balance,
        currency: user.currency
      });
    } catch (error) {
      console.error("BALANCE ERROR:", error);

      return res.status(500).json({
        success: false,
        message: "Could not update balance"
      });
    }
  }
);

/* =========================
   404
========================= */

app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: "Route not found"
  });
});

/* =========================
   START SERVER
========================= */

async function startServer() {
  try {
    await mongoose.connect(MONGODB_URI);

    console.log("MongoDB connected successfully");

    app.listen(PORT, () => {
      console.log(
        `Zonguru backend running on port ${PORT}`
      );
    });
  } catch (error) {
    console.error(
      "MongoDB connection failed:",
      error.message
    );

    process.exit(1);
  }
}

startServer();
