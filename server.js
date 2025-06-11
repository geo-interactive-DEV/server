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

// JSON FILE SETUP
const USERS_FILE = path.join(__dirname, "users.json");

let users = [];
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

// In-memory chat messages (reset on restart)
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

// --- ROUTES ---

// Register
app.post("/register", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ success: false, message: "Missing username or password" });
  }
  if (users.find((u) => u.username === username)) {
    return res.status(400).json({ success: false, message: "Username already exists" });
  }
  users.push({ username, password });
  saveUsers();
  res.json({ success: true, message: "User registered successfully" });
});

// Login
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ success: false, message: "Missing username or password" });
  }
  const user = users.find((u) => u.username === username && u.password === password);
  if (!user) return res.status(401).json({ success: false, message: "Invalid credentials" });

  const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: "2h" });
  res.json({ success: true, token });
});

// Profile
app.get("/profile", authenticateToken, (req, res) => {
  const user = users.find((u) => u.username === req.user.username);
  if (!user) return res.status(404).json({ success: false, message: "User not found" });
  res.json({ success: true, username: user.username });
});

// Get last 50 chat messages
app.get("/chat/messages", authenticateToken, (req, res) => {
  const recentMessages = chatMessages.slice(-50);
  res.json({ success: true, messages: recentMessages });
});

// Post a new chat message
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
  if (chatMessages.length > 1000) chatMessages.shift();
  res.json({ success: true, message: "Message sent", data: msgObj });
});

// Home route
app.get("/", (req, res) => {
  res.send("Server is running. Use API endpoints to interact.");
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}, MongoDB removed - JSON file mode only.`);
});
