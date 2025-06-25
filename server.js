require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const app = express();
const PORT = process.env.PORT || 3000;

const JWT_SECRET = process.env.JWT_SECRET || "joeisnotgay"; // Change this in production!
const MONGO_URI = process.env.MONGO_URI;

if (!MONGO_URI) {
  console.error("Error: MONGO_URI environment variable not set");
  process.exit(1);
}

app.use(cors());
app.use(bodyParser.json());

// MongoDB connection
mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("MongoDB connected"))
  .catch((err) => {
    console.error("MongoDB connection error:", err);
    process.exit(1);
  });

// Schemas
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  passwordHash: { type: String, required: true },
  role: { type: String, default: "user" },
  points: { type: Number, default: 0 },
  dailyClaimDate: { type: Date, default: null },
  dailyStreak: { type: Number, default: 0 }
});

const banSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  bannedUntil: { type: Date, required: true }
});

const chatSchema = new mongoose.Schema({
  username: String,
  message: String,
  timestamp: { type: Date, default: Date.now }
});

// Models
const User = mongoose.model("User", userSchema);
const Ban = mongoose.model("Ban", banSchema);
const ChatMessage = mongoose.model("ChatMessage", chatSchema);

// Middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  if (!authHeader) return res.status(401).json({ success: false, message: "No authorization header" });

  const token = authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ success: false, message: "No token provided" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ success: false, message: "Invalid or expired token" });
    req.user = user;
    next();
  });
}

async function checkAdmin(req, res, next) {
  const user = await User.findOne({ username: req.user.username });
  if (!user || user.role !== "admin") {
    return res.status(403).json({ success: false, message: "Admin only" });
  }
  next();
}

async function isUserBanned(username) {
  const ban = await Ban.findOne({ username });
  return ban && ban.bannedUntil > new Date();
}

// Routes

// Register
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ success: false, message: "Missing username or password" });

  try {
    const existingUser = await User.findOne({ username });
    if (existingUser) return res.status(400).json({ success: false, message: "Username already exists" });

    const passwordHash = await bcrypt.hash(password, 10);
    const newUser = new User({ username, passwordHash });
    await newUser.save();

    res.json({ success: true, message: "User registered successfully" });
  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Login
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ success: false, message: "Missing username or password" });

  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(401).json({ success: false, message: "Invalid credentials" });

    const validPassword = await bcrypt.compare(password, user.passwordHash);
    if (!validPassword) return res.status(401).json({ success: false, message: "Invalid credentials" });

    const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: "2h" });
    res.json({ success: true, token });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Profile
app.get("/profile", authenticateToken, async (req, res) => {
  try {
    const user = await User.findOne({ username: req.user.username });
    if (!user) return res.status(404).json({ success: false, message: "User not found" });
    res.json({ success: true, username: user.username, role: user.role });
  } catch (err) {
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Get current points and streak info
app.get("/points", authenticateToken, async (req, res) => {
  try {
    const user = await User.findOne({ username: req.user.username });
    if (!user) return res.status(404).json({ success: false, message: "User not found" });

    // Check if claimed today by date only
    let claimedToday = false;
    if (user.dailyClaimDate) {
      const lastClaim = new Date(user.dailyClaimDate);
      const now = new Date();
      claimedToday = lastClaim.toDateString() === now.toDateString();
    }

    res.json({
      success: true,
      points: user.points,
      streak: user.dailyStreak,
      claimedToday
    });
  } catch (err) {
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// POST: Claim daily points with streak logic
app.post("/points/daily", authenticateToken, async (req, res) => {
  try {
    const user = await User.findOne({ username: req.user.username });
    if (!user) return res.status(404).json({ success: false, message: "User not found" });

    const now = new Date();
    const lastClaim = user.dailyClaimDate ? new Date(user.dailyClaimDate) : null;

    // Check if already claimed today (date only)
    if (lastClaim && lastClaim.toDateString() === now.toDateString()) {
      return res.json({
        success: false,
        message: "Daily points already claimed today.",
        points: user.points,
        streak: user.dailyStreak,
        claimedToday: true
      });
    }

    // Check if last claim was yesterday to continue streak
    const yesterday = new Date(now);
    yesterday.setDate(yesterday.getDate() - 1);

    let newStreak = 1;
    if (lastClaim && lastClaim.toDateString() === yesterday.toDateString()) {
      newStreak = user.dailyStreak + 1;
    }

    // Points: base 10 + 5 per day streak after the first day
    const pointsEarned = 10 + (newStreak - 1) * 5;

    user.points += pointsEarned;
    user.dailyClaimDate = now;
    user.dailyStreak = newStreak;

    await user.save();

    res.json({
      success: true,
      message: `You earned ${pointsEarned} points!`,
      points: user.points,
      streak: newStreak,
      pointsEarned,
      claimedToday: true
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// POST: Earn points manually (optional)
app.post("/points/earn", authenticateToken, async (req, res) => {
  const amount = parseInt(req.body.amount, 10) || 10;
  if (amount < 1) return res.status(400).json({ success: false, message: "Invalid amount" });

  try {
    const user = await User.findOneAndUpdate(
      { username: req.user.username },
      { $inc: { points: amount } },
      { new: true }
    );

    res.json({ success: true, message: `Earned ${amount} points`, points: user.points });
  } catch (err) {
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// POST: Spend points on reward
app.post("/points/spend", authenticateToken, async (req, res) => {
  const cost = parseInt(req.body.cost, 10);
  const rewardName = req.body.reward || "reward";

  if (!cost || cost < 1) return res.status(400).json({ success: false, message: "Invalid cost" });

  try {
    const user = await User.findOne({ username: req.user.username });
    if (!user) return res.status(404).json({ success: false, message: "User not found" });

    if (user.points < cost) {
      return res.status(400).json({ success: false, message: "Not enough points" });
    }

    user.points -= cost;
    await user.save();

    res.json({ success: true, message: `Redeemed ${rewardName}`, points: user.points });
  } catch (err) {
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Chat: Get messages
app.get("/chat/messages", authenticateToken, async (req, res) => {
  try {
    const messages = await ChatMessage.find().sort({ timestamp: -1 }).limit(50).lean();
    res.json({ success: true, messages: messages.reverse() });
  } catch (err) {
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Chat: Post message or ban command
app.post("/chat/messages", authenticateToken, async (req, res) => {
  const { message } = req.body;
  const username = req.user.username;

  if (!message || typeof message !== "string" || message.trim() === "") {
    return res.status(400).json({ success: false, message: "Invalid message" });
  }

  if (await isUserBanned(username)) {
    return res.status(403).json({ success: false, message: "You are banned from chatting." });
  }

  // Ban command
  if (message.toLowerCase().startsWith("ban ")) {
    const user = await User.findOne({ username });
    if (!user || user.role !== "admin") {
      return res.status(403).json({ success: false, message: "Admin only." });
    }

    const parts = message.trim().split(/\s+/);
    if (parts.length < 2) {
      return res.status(400).json({ success: false, message: "Format: ban username [days]" });
    }

    const targetUser = parts[1];
    let days = 7;

    if (parts[2]) {
      const d = parseInt(parts[2], 10);
      if (!isNaN(d) && d > 0) days = d;
    }

    const bannedUntil = new Date(Date.now() + days * 86400000);
    await Ban.findOneAndUpdate({ username: targetUser }, { username: targetUser, bannedUntil }, { upsert: true, new: true });

    return res.json({ success: true, message: `${targetUser} banned for ${days} day(s).` });
  }

  // Normal message
  try {
    const msgObj = new ChatMessage({ username, message: message.trim() });
    await msgObj.save();
    res.json({ success: true, message: "Message sent", data: msgObj });
  } catch (err) {
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Admin: Get full user info
app.get("/admin/user/:username", authenticateToken, checkAdmin, async (req, res) => {
  try {
    const username = req.params.username;
    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ success: false, message: "User not found" });

    const ban = await Ban.findOne({ username });
    const logs = await ChatMessage.find({ username }).sort({ timestamp: -1 }).limit(20).lean();

    res.json({
      username: user.username,
      role: user.role,
      banned: !!ban && ban.bannedUntil > new Date(),
      banReason: "Chat Ban",
      banExpiry: ban ? ban.bannedUntil : null,
      logs: logs.map(log => `[${new Date(log.timestamp).toLocaleString()}] ${log.message}`)
    });
  } catch (err) {
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Admin: View only ban info
app.get("/admin/ban/:username", authenticateToken, checkAdmin, async (req, res) => {
  try {
    const ban = await Ban.findOne({ username: req.params.username });
    if (!ban) return res.status(404).json({ success: false, message: "No ban found" });
    res.json({ username: ban.username, bannedUntil: ban.bannedUntil });
  } catch (err) {
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Admin: View chat logs
app.get("/admin/chatlogs/:username", authenticateToken, checkAdmin, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 10, 50);
    const before = req.query.before ? new Date(req.query.before) : new Date();

    const logs = await ChatMessage.find({
      username: req.params.username,
      timestamp: { $lt: before }
    }).sort({ timestamp: -1 }).limit(limit).lean();

    res.json({ logs });
  } catch (err) {
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Home route
app.get("/", (req, res) => {
  res.send("Server is running with MongoDB and JWT authentication.");
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
