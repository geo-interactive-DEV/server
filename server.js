require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs"); // changed to bcryptjs

const app = express();
const PORT = process.env.PORT || 3000;

const JWT_SECRET = process.env.JWT_SECRET || "joeisnotgay"; // Change this in production!
const MONGO_URI = process.env.MONGO_URI; // Your MongoDB connection string

if (!MONGO_URI) {
  console.error("Error: MONGO_URI environment variable not set");
  process.exit(1);
}

app.use(cors());
app.use(bodyParser.json());

// Connect to MongoDB
mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("MongoDB connected"))
  .catch((err) => {
    console.error("MongoDB connection error:", err);
    process.exit(1);
  });

// Define User Schema with unique username and role field
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  passwordHash: { type: String, required: true },
  role: { type: String, default: "user" } // roles: user, admin, etc.
});

// Ban schema to track banned users
const banSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  bannedUntil: { type: Date, required: true }
});

const chatSchema = new mongoose.Schema({
  username: String,
  message: String,
  timestamp: { type: Date, default: Date.now },
});

const User = mongoose.model("User", userSchema);
const Ban = mongoose.model("Ban", banSchema);
const ChatMessage = mongoose.model("ChatMessage", chatSchema);

// Middleware to verify JWT token
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

// Helper to check if user is banned
async function isUserBanned(username) {
  const ban = await Ban.findOne({ username });
  if (!ban) return false;
  return ban.bannedUntil > new Date();
}

// --- ROUTES ---

// Register
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ success: false, message: "Missing username or password" });
  }
  try {
    const existingUser = await User.findOne({ username });
    if (existingUser) return res.status(400).json({ success: false, message: "Username already exists" });

    const passwordHash = await bcrypt.hash(password, 10);
    const newUser = new User({ username, passwordHash, role: "user" });
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
  if (!username || !password) {
    return res.status(400).json({ success: false, message: "Missing username or password" });
  }
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
    console.error("Profile error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Get last 50 chat messages
app.get("/chat/messages", authenticateToken, async (req, res) => {
  try {
    const messages = await ChatMessage.find()
      .sort({ timestamp: -1 })
      .limit(50)
      .lean();
    res.json({ success: true, messages: messages.reverse() }); // oldest first
  } catch (err) {
    console.error("Get messages error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Post a new chat message (with ban check and ban command)
app.post("/chat/messages", authenticateToken, async (req, res) => {
  const { message } = req.body;
  const username = req.user.username;

  if (!message || typeof message !== "string" || message.trim() === "") {
    return res.status(400).json({ success: false, message: "Invalid message" });
  }

  // Check if user is banned
  if (await isUserBanned(username)) {
    return res.status(403).json({ success: false, message: "You are banned from chatting." });
  }

  // Check if message is a ban command
  if (message.toLowerCase().startsWith("ban ")) {
    // Only allow admins to ban
    const user = await User.findOne({ username });
    if (!user || user.role !== "admin") {
      return res.status(403).json({ success: false, message: "You do not have permission to ban users." });
    }

    const parts = message.trim().split(/\s+/); // split by whitespace
    // ban username [amount]
    if (parts.length < 2) {
      return res.status(400).json({ success: false, message: "Invalid ban command format. Usage: ban username [days]" });
    }

    const targetUser = parts[1];
    let days = 7; // default ban days

    if (parts.length >= 3) {
      const parsedDays = parseInt(parts[2], 10);
      if (!isNaN(parsedDays) && parsedDays > 0) {
        days = parsedDays;
      } else {
        return res.status(400).json({ success: false, message: "Invalid number of days for ban." });
      }
    }

    const bannedUntil = new Date(Date.now() + days * 24 * 60 * 60 * 1000);

    // Upsert ban for the target user
    await Ban.findOneAndUpdate(
      { username: targetUser },
      { username: targetUser, bannedUntil },
      { upsert: true, new: true }
    );

    return res.json({ success: true, message: `${targetUser} banned for ${days} day(s).` });
  }

  // Normal message: save it
  try {
    const msgObj = new ChatMessage({
      username,
      message: message.trim(),
    });
    await msgObj.save();
    res.json({
      success: true,
      message: "Message sent",
      data: {
        username: msgObj.username,
        message: msgObj.message,
        timestamp: msgObj.timestamp,
        _id: msgObj._id,
      },
    });
  } catch (err) {
    console.error("Save message error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});
sync function checkAdmin(req, res, next) {
  const user = await User.findOne({ username: req.user.username });
  if (!user || user.role !== "admin") {
    return res.status(403).json({ success: false, message: "Admin only" });
  }
  next();
}

app.get("/admin/user/:username", authenticateToken, checkAdmin, async (req, res) => {
  try {
    const user = await User.findOne({ username: req.params.username });
    if (!user) return res.status(404).json({ success: false, message: "User not found" });
    res.json({ username: user.username, role: user.role });
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

    const logs = await ChatMessage.find({
      username: req.params.username,
      timestamp: { $lt: before }
    })
    .sort({ timestamp: -1 })
    .limit(limit)
    .lean();

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
