const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const { MongoClient, ServerApiVersion } = require("mongodb");

const app = express();
const PORT = 3000;

const JWT_SECRET = "joeisnotgay"; // replace with env var or secure secret in production

app.use(cors());
app.use(bodyParser.json());

// --- MongoDB Setup ---
const MONGO_USER = "cogotg199";
const MONGO_PASS = "Imyourpassword";  // <-- your password here
const MONGO_DB_NAME = "mydatabase";   // replace with your DB name

const MONGO_URI = `mongodb+srv://${MONGO_USER}:${MONGO_PASS}@cluster0.quncdr4.mongodb.net/${MONGO_DB_NAME}?retryWrites=true&w=majority&appName=Cluster0`;

const client = new MongoClient(MONGO_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

let usersCollection;
let chatCollection;

async function connectMongo() {
  try {
    await client.connect();
    console.log("Connected successfully to MongoDB");

    const db = client.db(MONGO_DB_NAME);
    usersCollection = db.collection("users");
    chatCollection = db.collection("chatmessages");

  } catch (err) {
    console.error("MongoDB connection error:", err);
    process.exit(1);
  }
}
connectMongo();

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
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ success: false, message: "Missing username or password" });

  try {
    const existing = await usersCollection.findOne({ username });
    if (existing) return res.status(400).json({ success: false, message: "Username already exists" });

    // WARNING: Store hashed passwords in production!
    await usersCollection.insertOne({ username, password });

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
    const user = await usersCollection.findOne({ username, password });
    if (!user) return res.status(401).json({ success: false, message: "Invalid credentials" });

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
    const user = await usersCollection.findOne({ username: req.user.username });
    if (!user) return res.status(404).json({ success: false, message: "User not found" });
    res.json({ success: true, username: user.username });
  } catch (err) {
    console.error("Profile error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Get last 50 chat messages
app.get("/chat/messages", authenticateToken, async (req, res) => {
  try {
    const messages = await chatCollection.find()
      .sort({ timestamp: -1 })
      .limit(50)
      .toArray();
    res.json({ success: true, messages: messages.reverse() });
  } catch (err) {
    console.error("Get messages error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Post a new chat message
app.post("/chat/messages", authenticateToken, async (req, res) => {
  const { message } = req.body;
  if (!message || typeof message !== "string" || message.trim() === "") {
    return res.status(400).json({ success: false, message: "Invalid message" });
  }

  try {
    const msgObj = {
      username: req.user.username,
      message: message.trim(),
      timestamp: new Date(),
    };
    await chatCollection.insertOne(msgObj);
    res.json({ success: true, message: "Message sent", data: msgObj });
  } catch (err) {
    console.error("Save message error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Home route
app.get("/", (req, res) => {
  res.send("Server is running. Use API endpoints to interact.");
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
