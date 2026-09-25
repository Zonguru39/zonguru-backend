const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");

const app = express();

app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_THIS_SECRET";

// MongoDB
mongoose
  .connect(process.env.MONGO_URL)
  .then(() => console.log("MongoDB Connected"))
  .catch((error) => console.error("MongoDB Error:", error.message));

// User model
const User = mongoose.model(
  "User",
  new mongoose.Schema(
    {
      name: {
        type: String,
        required: true,
        trim: true
      },
      email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true
      },
      passwordHash: {
        type: String,
        required: true
      },
      role: {
        type: String,
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
    { timestamps: true }
  )
);

// JWT
function createToken(user) {
  return jwt.sign(
    {
      id: user._id.toString(),
      email: user.email,
      role: user.role
    },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

// Authentication
function auth(req, res, next) {
  const header = req.headers.authorization;

  if (!header || !header.startsWith("Bearer ")) {
    return res.status(401).json({
      success: false,
      message: "Login required"
    });
  }

  try {
    const token = header.split(" ")[1];
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({
      success: false,
      message: "Invalid or expired token"
    });
  }
}

// Admin only
async function adminOnly(req, res, next) {
  try {
    const user = await User.findById(req.user.id);

    if (!user || user.role !== "admin") {
      return res.status(403).json({
        success: false,
        message: "Admin access required"
      });
    }

    next();
  } catch {
    res.status(500).json({
      success: false,
      message: "Server error"
    });
  }
}

// Health check
app.get("/", (req, res) => {
  res.json({
    success: true,
    service: "Zonguru Backend",
    status: "online"
  });
});

// Register
app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        success: false,
        message: "Name, email and password are required"
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: "Password must contain at least 6 characters"
      });
    }

    const normalizedEmail = email.toLowerCase().trim();

    const existing = await User.findOne({
      email: normalizedEmail
    });

    if (existing) {
      return res.status(409).json({
        success: false,
        message: "Email already registered"
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const user = await User.create({
      name: name.trim(),
      email: normalizedEmail,
      passwordHash,
      role: "user",
      balance: 0,
      currency: "USDT"
    });

    const token = createToken(user);

    res.status(201).json({
      success: true,
      message: "Registration successful",
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        balance: user.balance,
        currency: user.currency
      }
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      message: "Registration failed"
    });
  }
});

// Login
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const normalizedEmail = String(email || "")
      .toLowerCase()
      .trim();

    const user = await User.findOne({
      email: normalizedEmail
    });

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password"
      });
    }

    const validPassword = await bcrypt.compare(
      password,
      user.passwordHash
    );

    if (!validPassword) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password"
      });
    }

    const token = createToken(user);

    res.json({
      success: true,
      message: "Login successful",
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        balance: user.balance,
        currency: user.currency
      }
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      message: "Login failed"
    });
  }
});

// Current user
app.get("/api/me", auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found"
      });
    }

    res.json({
      success: true,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        balance: user.balance,
        currency: user.currency
      }
    });
  } catch {
    res.status(500).json({
      success: false,
      message: "Server error"
    });
  }
});

// Admin: list users
app.get(
  "/api/admin/users",
  auth,
  adminOnly,
  async (req, res) => {
    try {
      const users = await User.find().select(
        "-passwordHash"
      );

      res.json({
        success: true,
        users
      });
    } catch {
      res.status(500).json({
        success: false,
        message: "Failed to load users"
      });
    }
  }
);

// Admin: change balance
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

      const user = await User.findByIdAndUpdate(
        req.params.id,
        { balance: numericAmount },
        { new: true }
      );

      if (!user) {
        return res.status(404).json({
          success: false,
          message: "User not found"
        });
      }

      res.json({
        success: true,
        message: "Balance updated",
        balance: user.balance,
        currency: user.currency
      });
    } catch {
      res.status(500).json({
        success: false,
        message: "Failed to update balance"
      });
    }
  }
);

app.listen(PORT, () => {
  console.log(
    `Zonguru backend running on port ${PORT}`
  );
});
