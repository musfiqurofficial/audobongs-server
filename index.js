const express = require("express");
const app = express();
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const cors = require("cors");
const bcrypt = require("bcryptjs"); // Added for password hashing
const jwt = require("jsonwebtoken"); // Added for generating JWTs

require("dotenv").config();

app.use(express.json());
app.use(cors());

dotenv.config();

const database = process.env.MONGOLAB_URI;

mongoose
  .connect(database, { useUnifiedTopology: true, useNewUrlParser: true })
  .then(() => console.log("Mongodb connected"))
  .catch((err) => console.log(err));

// User schema with unique email index
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true},
});

const User = mongoose.model("User", userSchema);

// Signup API endpoint
app.post("/api/signup", async (req, res) => {
    try {
      const { email, password } = req.body;
      console.log(req.body);
  
      // Check for existing user with the same email
      const existingUser = await User.findOne({ email });
  
      if (existingUser) {
        // If user exists, check if the provided password is correct
        const isPasswordValid = await bcrypt.compare(
          password,
          existingUser.password
        );
  
        if (isPasswordValid) {
          // Generate a JWT (optional for authentication)
          const token = jwt.sign(
            { userId: existingUser._id },
            process.env.JWT_SECRET,
            { expiresIn: "1h" }
          );
  
          return res.json({
            message: "Signin successful",
            token,
          });
        } else {
          return res.status(400).json({ message: "Incorrect password" });
        }
      } else {
        // Hash the password and create a new user
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ email, password: hashedPassword });
        await newUser.save();
  
        // Generate a JWT (optional for authentication)
        const token = jwt.sign({ userId: newUser._id }, process.env.JWT_SECRET, {
          expiresIn: "250h",
        });
  
        return res.json({
          message: "User created successfully",
          token,
        });
      }
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: "Error creating or signing in user" });
    }
  });

app.get('', (req, res) => {
    res.send("Hello World")
});

const PORT = process.env.PORT || 8001;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
