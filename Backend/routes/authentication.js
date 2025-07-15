import { Router } from "express";
import User from "../models/User.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import { serialize } from "cookie";

dotenv.config();

const router = Router();

const jwtSecret = process.env.JWT_SECRET;
const jwtExpiration = "1h";

// Register User

router.post("/register", async (req, res) => {
  try {
    let { name, email, password } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(403).send({ error: "Email already exists" });
    }

    const saltRounds = await bcrypt.genSalt(10);
    password = await bcrypt.hash(password, saltRounds);

    const user = await User.create({
      name,
      email,
      password,
      isAdmin: "user",
    });

    const returnUser = {
      name: user.name,
      email: user.email,
      _id: user._id,
    };

    res.status(201).send({
      message: "User created succesfully",
      returnUser,
    });
  } catch (err) {
    return res.status(500).send({ error: "server error" });
  }
});

// Login User

router.post("/login", async (req, res) => {
  try {
    let { email, password } = req.body;

    // --- בדיקות נוספות להתחלה ---
    console.log("Login attempt received.");
    console.log("Received email:", email);
    console.log(
      "Received password (first 3 chars for security):",
      password ? password.substring(0, 3) + "..." : "No password"
    );
    // --- סוף בדיקות נוספות ---

    const user = await User.findOne({ email });

    // --- לוג: בדיקה האם המשתמש נמצא ---
    if (!user) {
      console.log("Login failed: User not found for email:", email);
      return res.status(400).send({ error: "Invalid email or password" });
    }
    console.log("User found in DB for email:", email);
    console.log(
      "Stored hashed password (from DB):",
      user.password
        ? user.password.substring(0, 10) + "..."
        : "No hashed password"
    ); // הצג רק חלק מה-hash

    const isMatch = await bcrypt.compare(password, user.password);

    // --- לוג: בדיקת השוואת סיסמה ---
    console.log("Result of bcrypt.compare (isMatch):", isMatch);
    if (!isMatch) {
      console.log("Login failed: Password mismatch for email:", email);
      return res.status(400).send({ error: "Invalid password or email" });
    }
    console.log("Password matched for user:", email);

    const payload = {
      _id: user._id,
      name: user.name,
      email: user.email,
      isAdmin: user.isAdmin,
    };

    jwt.sign(payload, jwtSecret, { expiresIn: jwtExpiration }, (err, token) => {
      if (err) {
        console.log("failed to create token", err);
        console.error("JWT Token creation error:", err); // לוג שגיאה מפורט יותר
        return res.status(500).send({ error: "server error" });
      }

      const serialized = serialize("token", token, {
        httpOnly: true,
        secure: true,
        sameSite: "None",
        maxAge: 60 * 60 * 24 * 30,
        path: "/",
      });
      res.setHeader("Set-Cookie", serialized);
      console.log("Set-Cookie header sent with token."); // לוג: Cookie נשלח

      const returnUser = {
        name: user.name,
        email: user.email,
        _id: user._id,
        isAdmin: user.isAdmin,
      };

      const message =
        user.isAdmin === "admin"
          ? "Admin logged in successfully"
          : "User logged in succesfully";

      console.log("Login successful for user:", email, "Message:", message); // לוג: התחברות מוצלחת סופית

      res.status(200).send({
        message,
        user: returnUser,
        token: token,
      });
    });
  } catch (err) {
    console.error("Failed login attempt (catch block error):", err); // לוג מפורט לשגיאות כלליות
    return res.status(500).send({ error: "server error" });
  }
});

////

router.post("/logout", async (req, res) => {
  const serialized = serialize("token", "", {
    httpOnly: true,
    secure: true,
    sameSite: "None",
    expires: new Date(0),
    path: "/",
  });

  res.setHeader("Set-Cookie", serialized);
  return res.status(200).json({ message: "Logged out successfully" });
});

////

router.get("/me", async (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).send({ error: "Not authenticated" });

  try {
    const decoded = jwt.verify(token, jwtSecret);
    res.status(200).send({
      _id: decoded._id,
      email: decoded.email,
      name: decoded.name,
      isAdmin: decoded.isAdmin,
    });
  } catch (err) {
    return res.status(403).send({ error: "Invalid token" });
  }
});

export default router;
