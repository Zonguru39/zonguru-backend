const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();

app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_THIS_SECRET";

// Demo in-memory database.
// Later we will connect a real database.
const users = [];

function createToken(user) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      role: user.role
    },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

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
  } catch {
    return res.status(401).json({
      success: false,
      message: "Invalid or expired token"
    });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({
      success: false,
      message: "Admin access required"
    });
  }

  next();
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

    const existing = users.find(
      (user) => user.email === normalizedEmail
    );

    if (existing) {
      return res.status(409).json({
        success: false,
        message: "Email already registered"
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const user = {
      id: String(Date.now()),
      name: name.trim(),
      email: normalizedEmail,
      passwordHash,
      role: "user",
      balance: 0,
      currency: "USDT"
    };

    users.push(user);

    const token = createToken(user);

    res.status(201).json({
      success: true,
      message: "Registration successful",
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        balance: user.balance,
        currency: user.currency
      }
    });
  } catch (error) {
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

    const user = users.find(
      (item) => item.email === normalizedEmail
    );

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
        id: user.id,
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
      message: "Login failed"
    });
  }
});

// Current user
app.get("/api/me", auth, (req, res) => {
  const user = users.find(
    (item) => item.id === req.user.id
  );

  if (!user) {
    return res.status(404).json({
      success: false,
      message: "User not found"
    });
  }

  res.json({
    success: true,
    user: {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      balance: user.balance,
      currency: user.currency
    }
  });
});

// Admin: list users
app.get("/api/admin/users", auth, adminOnly, (req, res) => {
  res.json({
    success: true,
    users: users.map((user) => ({
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      balance: user.balance,
      currency: user.currency
    }))
  });
});

// Admin: change balance
app.post(
  "/api/admin/users/:id/balance",
  auth,
  adminOnly,
  (req, res) => {
    const { amount } = req.body;

    const user = users.find(
      (item) => item.id === req.params.id
    );

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found"
      });
    }

    const numericAmount = Number(amount);

    if (!Number.isFinite(numericAmount)) {
      return res.status(400).json({
        success: false,
        message: "Invalid amount"
      });
    }

    user.balance = numericAmount;

    res.json({
      success: true,
      message: "Balance updated",
      balance: user.balance,
      currency: user.currency
    });
  }
);

app.listen(PORT, () => {
  console.log(`Zonguru backend running on port ${PORT}`);
});
