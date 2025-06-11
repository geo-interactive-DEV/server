require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const fs = require("fs");
const path = require("path");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = 3000; // fixed port as you requested

const JWT_SECRET = process.env.JWT_SECRET || "joeisnotgay"; // Use env var in prod

app.use(cors());
app.use(bodyParser.json());

const useMongo = process.env.USE_MONGO === "false"; // set env USE_MONGO=true to enable

// --- JSON FILE SETUP (if useMongo = false) ---
const USERS_FILE = path.join(__dirname, "users.json");

let users = [];
if (!useMongo) {
  if (fs.existsSync(USERS_FILE)) {
    try {
      users = JSON.parse(fs.readFileSync(USERS_FILE, "utf8"));
    } catch (err) {
      console.error("Failed to parse users.json, initializing empty users array:", err);
      users = [];
    }
  } else {
    try {
      fs.writeFileSync(USERS_FILE, JSON.stringify([]));
    } catch (err) {
      console.error("Failed to create users.json file:", err);
    }
  }
  function saveUsers() {
    try {
      fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
    } catch (err) {
      console.error("Failed to save users:", err);
    }
  }
}

// --- MONGODB SETUP ---
let UserModel = null;
let ChatModel = null;
let mongoose = null;

if (useMongo) {
  mongoose = require("mongoose");
  const MONGO_URI = process.env.MONGO_URI;
  if (!MONGO_URI) {
    console.error("MONGO_URI environment variable required for MongoDB mode");
    process.exit(1);
  }

  mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log("MongoDB connected"))
    .catch((err) => {
      console.error("MongoDB connection error:", err);
      process.exit(1);
    });

  const userSchema = new mongoose.Schema({
    username: { type: String, unique: true, required: true },
    password: { type: String, required: true }, // WARNING: store hashed passwords in prod
  });

  const chatSchema = new mongoose.Schema({
    username: String,
    message: String,
    timestamp: { type: Date, default: Date.now },
  });

  UserModel = mongoose.model("User", userSchema);
  ChatModel = mongoose.model("ChatMessage", chatSchema);
}

// --- In-memory chat for JSON mode ---
let chatMessages = [];

// Middleware to verify JWT token (same for both modes)
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

// --- ROUTES ---

// Register
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ success: false, message: "Missing username or password" });
  }

  if (useMongo) {
    try {
      const existing = await UserModel.findOne({ username });
      if (existing) return res.status(400).json({ success: false, message: "Username already exists" });
      const user = new UserModel({ username, password });
      await user.save();
      res.json({ success: true, message: "User registered successfully" });
    } catch (err) {
      console.error("MongoDB register error:", err);
      res.status(500).json({ success: false, message: "Server error" });
    }
  } else {
    if (users.find((u) => u.username === username)) {
      return res.status(400).json({ success: false, message: "Username already exists" });
    }
    users.push({ username, password });
    saveUsers();
    res.json({ success: true, message: "User registered successfully" });
  }
});

// Login
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ success: false, message: "Missing username or password" });
  }

  if (useMongo) {
    try {
      const user = await UserModel.findOne({ username, password });
      if (!user) return res.status(401).json({ success: false, message: "Invalid credentials" });
      const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: "2h" });
      return res.json({ success: true, token });
    } catch (err) {
      console.error("MongoDB login error:", err);
      return res.status(500).json({ success: false, message: "Server error" });
    }
  } else {
    const user = users.find((u) => u.username === username && u.password === password);
    if (!user) return res.status(401).json({ success: false, message: "Invalid credentials" });
    const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: "2h" });
    res.json({ success: true, token });
  }
});

// Profile
app.get("/profile", authenticateToken, async (req, res) => {
  if (useMongo) {
    try {
      const user = await UserModel.findOne({ username: req.user.username });
      if (!user) return res.status(404).json({ success: false, message: "User not found" });
      res.json({ success: true, username: user.username });
    } catch (err) {
      console.error("MongoDB profile error:", err);
      res.status(500).json({ success: false, message: "Server error" });
    }
  } else {
    const user = users.find((u) => u.username === req.user.username);
    if (!user) return res.status(404).json({ success: false, message: "User not found" });
    res.json({ success: true, username: user.username });
  }
});

// Get last 50 chat messages
app.get("/chat/messages", authenticateToken, async (req, res) => {
  if (useMongo) {
    try {
      const messages = await ChatModel.find()
        .sort({ timestamp: -1 })
        .limit(50)
        .lean();
      res.json({ success: true, messages: messages.reverse() }); // reverse chronological to chronological
    } catch (err) {
      console.error("MongoDB get messages error:", err);
      res.status(500).json({ success: false, message: "Server error" });
    }
  } else {
    const recentMessages = chatMessages.slice(-50);
    res.json({ success: true, messages: recentMessages });
  }
});

// Post a new chat message
app.post("/chat/messages", authenticateToken, async (req, res) => {
  const { message } = req.body;
  if (!message || typeof message !== "string" || message.trim() === "") {
    return res.status(400).json({ success: false, message: "Invalid message" });
  }

  if (useMongo) {
    try {
      const msgObj = new ChatModel({
        username: req.user.username,
        message: message.trim(),
      });
      await msgObj.save();
      res.json({ success: true, message: "Message sent", data: msgObj });
    } catch (err) {
      console.error("MongoDB save message error:", err);
      res.status(500).json({ success: false, message: "Server error" });
    }
  } else {
    const msgObj = {
      username: req.user.username,
      message: message.trim(),
      timestamp: Date.now(),
    };
    chatMessages.push(msgObj);
    if (chatMessages.length > 1000) chatMessages.shift();
    res.json({ success: true, message: "Message sent", data: msgObj });
  }
});

// Home route
app.get("/", (req, res) => {
  res.send("Server is running. Use API endpoints to interact.");
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}, MongoDB mode: ${useMongo}`);
});

/*
IMPORTANT:

- To use MongoDB mode:
  1) Set environment variables:
     - USE_MONGO=true
     - MONGO_URI=your_mongodb_connection_string
     - (optionally) JWT_SECRET=your_jwt_secret

- To use JSON file mode:
  1) Set USE_MONGO=false or leave unset
  2) Your data is stored in users.json but beware ephemeral storage on hosts like Render.

- Passwords are stored in plain text in both modes here. Use bcrypt or similar hashing in production.

- MongoDB collections used:
  - users
  - chatmessages

- Chat messages in JSON mode are in-memory only (reset on server restart).

*/

