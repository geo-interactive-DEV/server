const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const fs = require("fs");
const path = require("path");
const jwt = require("jsonwebtoken");

const app = express();
// Use Render's assigned port or fallback to 3000 for local dev
const PORT = process.env.PORT || 3000;

const JWT_SECRET = "joeisnotgay"; // Replace with env var or safer secret in production

app.use(cors());
app.use(bodyParser.json());

const USERS_FILE = path.join(__dirname, "users.json");

// Load or initialize users from JSON file on startup
let users = [];
if (fs.existsSync(USERS_FILE)) {
  try {
    users = JSON.parse(fs.readFileSync(USERS_FILE, "utf8"));
  } catch (err) {
    console.error("Failed to parse users.json, initializing empty users array:", err);
    users = [];
  }
} else {
  // If users.json doesn't exist, create an empty one
  try {
    fs.writeFileSync(USERS_FILE, JSON.stringify([]));
  } catch (err) {
    console.error("Failed to create users.json file:", err);
  }
}

// Save users array back to JSON file
function saveUsers() {
  try {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
  } catch (err) {
    console.error("Failed to save users:", err);
  }
}

// In-memory chat messages store — this data will be lost on restart
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

// Register a new user
app.post("/register", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ success: false, message: "Missing username or password" });
  }
  if (users.find((u) => u.username === username)) {
    return res.status(400).json({ success: false, message: "Username already exists" });
  }
  // WARNING: Storing passwords in plain text is insecure! Use hashing in production!
  users.push({ username, password });
  saveUsers();
  res.json({ success: true, message: "User registered successfully" });
});

// Login existing user
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ success: false, message: "Missing username or password" });
  }
  const user = users.find((u) => u.username === username && u.password === password);
  if (!user) {
    return res.status(401).json({ success: false, message: "Invalid credentials" });
  }
  const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: "2h" });
  res.json({ success: true, token });
});

// Get user profile
app.get("/profile", authenticateToken, (req, res) => {
  const user = users.find((u) => u.username === req.user.username);
  if (!user) {
    return res.status(404).json({ success: false, message: "User not found" });
  }
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

  // Limit chatMessages array size to avoid memory issues
  if (chatMessages.length > 1000) chatMessages.shift();

  res.json({ success: true, message: "Message sent", data: msgObj });
});

// Add a simple home route to avoid 404 at root
app.get("/", (req, res) => {
  res.send("Server is running. Use API endpoints to interact.");
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

/*
IMPORTANT:

- This server stores users in a JSON file, but Render's filesystem is ephemeral,
  so any changes (like new registrations) will be lost on redeploy or restart.

- For production, move user and chat storage to a persistent database such as
  MongoDB Atlas, Firebase, or Supabase.

- Passwords are stored in plain text here — NEVER do this in production.
  Use bcrypt or similar hashing libraries to store passwords securely.

*/
