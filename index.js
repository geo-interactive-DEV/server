const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const fs = require("fs");
const path = require("path");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = 3000;
const JWT_SECRET = "joeisnotgay"; // Replace with env var or safer secret

app.use(cors());
app.use(bodyParser.json());

const USERS_FILE = path.join(__dirname, "users.json");

// Load or initialize users
let users = [];
if (fs.existsSync(USERS_FILE)) {
  try {
    users = JSON.parse(fs.readFileSync(USERS_FILE, "utf8"));
  } catch {
    users = [];
  }
} else {
  fs.writeFileSync(USERS_FILE, JSON.stringify([]));
}

function saveUsers() {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

// In-memory chat messages store
// For production, replace with database or persistent store
let chatMessages = [];

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

// Register route
app.post("/register", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ success: false, message: "Missing username or password" });
  }
  if (users.find((u) => u.username === username)) {
    return res.status(400).json({ success: false, message: "Username already exists" });
  }
  users.push({ username, password }); // WARNING: store hashed passwords in real apps
  saveUsers();
  res.json({ success: true, message: "User registered successfully" });
});

// Login route
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ success: false, message: "Missing username or password" });
  }
  const user = users.find((u) => u.username === username && u.password === password);
  if (!user) {
    return res.status(401).json({ success: false, message: "Invalid credentials" });
  }
  // Generate JWT token
  const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: "2h" });
  res.json({ success: true, token });
});

// Profile route
app.get("/profile", authenticateToken, (req, res) => {
  const user = users.find((u) => u.username === req.user.username);
  if (!user) {
    return res.status(404).json({ success: false, message: "User not found" });
  }
  res.json({ success: true, username: user.username });
});

// Chat routes

// Get last 50 messages (can add pagination later)
app.get("/chat/messages", authenticateToken, (req, res) => {
  // Return last 50 messages in chronological order
  const recentMessages = chatMessages.slice(-50);
  res.json({ success: true, messages: recentMessages });
});

// Post a new message
app.post("/chat/messages", authenticateToken, (req, res) => {
  const { message } = req.body;
  if (!message || typeof message !== "string" || message.trim() === "") {
    return res.status(400).json({ success: false, message: "Invalid message" });
  }
  const msgObj = {
    username: req.user.username,
    message: message.trim(),
    timestamp: Date.now(),
  };
  chatMessages.push(msgObj);

  // Optional: limit chatMessages array size to avoid memory issues
  if (chatMessages.length > 1000) chatMessages.shift();

  res.json({ success: true, message: "Message sent", data: msgObj });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
