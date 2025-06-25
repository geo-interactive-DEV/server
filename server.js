require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const app = express();
const PORT = process.env.PORT || 3000;

const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_THIS_SECRET";
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
  points: { type: Number, default: 0 }
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
  const token = authHeader?.split(" ")[1];
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
app.get("/", (req, res) => {
  res.send("Server is running with MongoDB and JWT authentication.");
});

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
    if (!user || !(await bcrypt.compare(password, user.passwordHash)))
      return res.status(401).json({ success: false, message: "Invalid credentials" });

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

// Points
app.get("/points", authenticateToken, async (req, res) => {
  try {
    const user = await User.findOne({ username: req.user.username });
    if (!user) return res.status(404).json({ success: false, message: "User not found" });
    res.json({ success: true, points: user.points });
  } catch (err) {
    res.status(500).json({ success: false, message: "Server error" });
  }
});

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

app.post("/points/spend", authenticateToken, async (req, res) => {
  const cost = parseInt(req.body.cost, 10);
  const rewardName = req.body.reward || "reward";

  if (!cost || cost < 1) return res.status(400).json({ success: false, message: "Invalid cost" });

  try {
    const user = await User.findOne({ username: req.user.username });
    if (!user) return res.status(404).json({ success: false, message: "User not found" });

    if (user.points < cost)
      return res.status(400).json({ success: false, message: "Not enough points" });

    user.points -= cost;
    await user.save();
    res.json({ success: true, message: `Redeemed ${rewardName}`, points: user.points });
  } catch (err) {
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Chat Messages
app.get("/chat/messages", authenticateToken, async (req, res) => {
  try {
    const messages = await ChatMessage.find().sort({ timestamp: -1 }).limit(50).lean();
    res.json({ success: true, messages: messages.reverse() });
  } catch (err) {
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.post("/chat/messages", authenticateToken, async (req, res) => {
  const { message } = req.body;
  const username = req.user.username;

  if (!message?.trim()) return res.status(400).json({ success: false, message: "Invalid message" });
  if (await isUserBanned(username)) return res.status(403).json({ success: false, message: "You are banned." });

  if (message.toLowerCase().startsWith("ban ")) {
    const user = await User.findOne({ username });
    if (!user || user.role !== "admin") return res.status(403).json({ success: false, message: "Admin only" });

    const [_, target, daysStr] = message.trim().split(/\s+/);
    const days = parseInt(daysStr, 10) || 7;
    const bannedUntil = new Date(Date.now() + days * 86400000);
    await Ban.findOneAndUpdate({ username: target }, { username: target, bannedUntil }, { upsert: true });
    return res.json({ success: true, message: `${target} banned for ${days} days.` });
  }

  try {
    const msgObj = new ChatMessage({ username, message: message.trim() });
    await msgObj.save();
    res.json({ success: true, message: "Message sent", data: msgObj });
  } catch (err) {
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Admin routes
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
      banExpiry: ban ? ban.bannedUntil : null,
      logs: logs.map(log => `[${new Date(log.timestamp).toLocaleString()}] ${log.message}`)
    });
  } catch (err) {
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.get("/admin/ban/:username", authenticateToken, checkAdmin, async (req, res) => {
  try {
    const ban = await Ban.findOne({ username: req.params.username });
    if (!ban) return res.status(404).json({ success: false, message: "No ban found" });
    res.json({ username: ban.username, bannedUntil: ban.bannedUntil });
  } catch (err) {
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.get("/admin/chatlogs/:username", authenticateToken, checkAdmin, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 10, 50);
    const before = req.query.before ? new Date(req.query.before) : new Date();
    const logs = await ChatMessage.find({ username: req.params.username, timestamp: { $lt: before } })
      .sort({ timestamp: -1 }).limit(limit).lean();

    res.json({ logs });
  } catch (err) {
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
