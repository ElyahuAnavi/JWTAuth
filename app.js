require("dotenv").config();
const express = require("express");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

const app = express();
app.use(express.json());
app.use(cookieParser());

// In a real app, save the secret key in the environment file
const secretKey = process.env.SECRET_KEY || "your_secret_key";

// Mock db
const users = [];

const generateToken = (user) => {
  return jwt.sign({ id: user.id, username: user.username }, secretKey, { expiresIn: "1h" });
};

const verifyToken = (req, res, next) => {

  //checking for the presence of a token in the request headers under the "Authorization" key
  let token = req.headers["authorization"]?.split(" ")[1] || req.cookies.token;

  if (!token) {
    return res.status(403).json({ error: "Token is missing" });
  }

  try {
    const decoded = jwt.verify(token, secretKey);
    req.authData = decoded; // Token is valid, attach the decoded payload to the request object
    next();
  } 
  catch (err) {
    if (err instanceof jwt.TokenExpiredError) {
      return res.status(401).json({ error: "Token has expired" });
    } else if (err instanceof jwt.JsonWebTokenError) {
      return res.status(403).json({ error: "Token is invalid" });
    } else {
      return res.status(500).json({ error: "An error occurred while verifying the token" });
    }
  }
};

app.post("/signup", async (req, res) => {
  const { username, email, password } = req.body;

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = { id: users.length + 1, username, email, password: hashedPassword };
  users.push(newUser);

  const token = generateToken(newUser);
  res.json({ user: { id: newUser.id, username: newUser.username }, token });
});

app.post("/signin", async (req, res) => {
  const { username, password } = req.body;

  const user = users.find((u) => u.username === username);
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = generateToken(user);
  res.json({ user: { id: user.id, username: user.username }, token });
});

// Protected route, can only be accessed with a valid JWT token
app.use("/protected/*", verifyToken, (req, res) => {
  res.status(200).json({
    status: "success",
    data: req.user,
  });
});

const port = process.env.PORT || 3000;

app.listen(port, () => console.log(`Server running on port ${port}`));
