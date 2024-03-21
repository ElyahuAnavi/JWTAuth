const express = require("express");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());
app.use(cookieParser());

// In a real app, save the secret key in the environment file
const secretKey = "your_secret_key";

// Mock db
const users = [];

const generateToken = (user) => {
  return jwt.sign({ user }, secretKey, { expiresIn: "1h" });
};

const verifyToken = (req, res, next) => {
  let token;

  // Check if the token is present in the Authorization header
  const bearerHeader = req.headers["authorization"];
  token = bearerHeader ? bearerHeader.split(" ")[1] : null;

  // If the token is not found in the header, check if it's present in cookies
  if (!token && req.cookies) {
    token = req.cookies.token;
  }

  if (!token) {
    return res.status(403).json({ error: "Token is missing" });
  }

  jwt.verify(token, secretKey, (err, authData) => {
    if (err) {
      if (err.name === "TokenExpiredError") {
        return res.status(401).json({ error: "Token has expired" });
      } else {
        return res.status(403).json({ error: "Token is invalid" });
      }
    } else {
      // Token is valid, attach the decoded payload to the request object
      req.authData = authData;
      next();
    }
  });
};

app.post("/signup", (req, res) => {
  const { username, email, password } = req.body;

  // Mock user registration (in a real app, this would involve hashing the password and storing in a database)
  const newUser = { id: users.length + 1, username, email, password };
  users.push(newUser);

  const token = generateToken(newUser);
  res.json({ token });
});

app.post("/signin", (req, res) => {
  const { username, password } = req.body;

  // Mock user authentication (in a real app, this would check credentials against a database)
  const user = users.find(
    (u) => u.username === username && u.password === password
  );

  // TODO: Complete
});

// Protected route, can only be accessed with a valid JWT token
app.use("/protected/*", verifyToken, (req, res) => {
  res.status(200).json({
    status: "success",
    data: "data",
  });
});

const port = 3000;
app.listen(port, () => console.log(`Server running on port ${port}`));
