const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const crypto = require("crypto");

const app = express();

app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "ZONGURU_SECRET_2026";

const MONGO_URL = process.env.MONGO_URL;

if (!MONGO_URL) {
  console.error("ERROR: MONGO_URL is not set.");
  process.exit(1);
}

// ===============================
// Password Functions
// ===============================

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");

  const hash = crypto
    .scryptSync(password, salt, 64)
    .toString("hex");

  return `${salt}:${hash}`;
}

function verifyPassword(password, storedPassword) {
  try {
    const [salt, storedHash] = storedPassword.split(":");

    const hash = crypto
      .scryptSync(password, salt, 64)
      .toString("hex");

    return crypto.timingSafeEqual(
      Buffer.from(hash, "hex"),
      Buffer.from(storedHash, "hex")
    );
  } catch (error) {
    return false;
  }
}

// ===============================
// MongoDB
// ===============================

mongoose
  .connect(MONGO_URL)
  .then(() => {
    console.log("MongoDB connected successfully");
  })
  .catch((error) => {
    console.error("MongoDB connection failed:");
    console.error(error.message);
    process.exit(1);
  });

// ===============================
// User Schema
// ===============================

const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      minlength: 3
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

// ===============================
// JWT
// ===============================

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

// ===============================
// Auth Middleware
// ===============================

function auth(req, res, next) {
  const header = req.headers.authorization;

  if (!header || !header.startsWith("Bearer ")) {
    return res.status(401).json({
      success: false,
      message: "Login required"
    });
  }

  const token = header.split(" ")[1];

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Invalid or expired token"
    });
  }
}

// ===============================
// Admin Middleware
// ===============================

function adminOnly(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({
      success: false,
      message: "Admin access required"
    });
  }

  next();
}

// ===============================
// Health Check
// ===============================

app.get("/", (req, res) => {
  res.json({
    success: true,
    service: "Zonguru Backend",
    status: "online"
  });
});

// ===============================
// Register
// ===============================

app.post("/api/auth/register", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: "Username and password are required"
      });
    }

    const cleanUsername = String(username)
      .trim()
      .toLowerCase();

    if (cleanUsername.length < 3) {
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
      username: cleanUsername
    });

    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: "Username already registered"
      });
    }

    const passwordHash = hashPassword(password);

    const user = await User.create({
      username: cleanUsername,
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
    console.error("Registration error:", error);

    return res.status(500).json({
      success: false,
      message: "Registration failed"
    });
  }
});

// ===============================
// Login
// ===============================

app.post("/api/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: "Username and password are required"
      });
    }

    const cleanUsername = String(username)
      .trim()
      .toLowerCase();

    const user = await User.findOne({
      username: cleanUsername
    });

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Invalid username or password"
      });
    }

    const validPassword = verifyPassword(
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
    console.error("Login error:", error);

    return res.status(500).json({
      success: false,
      message: "Login failed"
    });
  }
});

// ===============================
// Current User
// ===============================

app.get("/api/me", auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);

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
    return res.status(500).json({
      success: false,
      message: "Failed to load user"
    });
  }
});

// ===============================
// Admin Users
// ===============================

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
      return res.status(500).json({
        success: false,
        message: "Failed to load users"
      });
    }
  }
);

// ===============================
// Admin Balance
// ===============================

app.post(
  "/api/admin/users/:id/balance",
  auth,
  adminOnly,
  async (req, res) => {
    try {
      const numericAmount = Number(req.body.amount);

      if (!Number.isFinite(numericAmount)) {
        return res.status(400).json({
          success: false,
          message: "Invalid amount"
        });
      }

      if (numericAmount < 0) {
        return res.status(400).json({
          success: false,
          message: "Balance cannot be negative"
        });
      }

      const user = await User.findById(req.params.id);

      if (!user) {
        return res.status(404).json({
          success: false,
          message: "User not found"
        });
      }

      user.balance = numericAmount;

      await user.save();

      return res.json({
        success: true,
        message: "Balance updated",
        balance: user.balance,
        currency: user.currency
      });

    } catch (error) {
      console.error("Balance update error:", error);

      return res.status(500).json({
        success: false,
        message: "Failed to update balance"
      });
    }
  }
);

// ===============================
// Start Server
// ===============================

app.listen(PORT, () => {
  console.log(`Zonguru backend running on port ${PORT}`);
});
