const express = require("express");
const port = 4000;
const app = express();
const cors = require("cors");
const mongoose = require("mongoose");
const User = require("./models/User");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");

//middleware
app.use(cors({ credentials: true, origin: "http://127.0.0.1:5173" }));
app.use(express.json());
app.use(cookieParser());

//encryption
const salt = bcrypt.genSaltSync(10);

//jwt
const secret = "f3qwrrhj23rug23rbdf2o83dn23dl3n2lduh";

//db
mongoose.connect(
  "route"
);

const generateJWT = (username, id) => {
  return jwt.sign({ username, id }, secret, {
    expiresIn: "30d",
  });
};

//apis
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  try {
    const userDoc = await User.create({
      username,
      password: bcrypt.hashSync(password, salt),
    });
    res.json(userDoc);
  } catch (err) {
    res.status(400).json(err);
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const userDoc = await User.findOne({ username });
  const passOk = bcrypt.compareSync(password, userDoc.password);
  if (passOk) {
    //logged in
    const token = generateJWT(username, userDoc._id);
    res.cookie("token", token, {
      httpOnly: true,
      sameSite: "strict",
      maxAge:30*24*60*60*1000
    });
    res.send("JWT cookie sent");
  } else {
    res.status(400).json("wrong credentials");
  }
});

app.get("/profile", (req, res) => {
  const token = req.cookies.token;
  if (token) {
    try {
      // Verify the token
      const decoded = jwt.verify(token, secret);

      // Decoded token will contain the user data you encoded earlier
      console.log(decoded);

      res.send(`Welcome ${decoded.username} to your profile!`);
    } catch (error) {
      res.status(401).json({ error: "Invalid token" });
    }
  } else {
    res.status(401).send("Token not found");
  }
});

app.listen(port, () => {
  console.log("Server started on port 4000");
});
