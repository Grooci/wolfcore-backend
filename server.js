require("dotenv").config();

console.log("MONGO_URL:", process.env.MONGO_URL);
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const validator = require("validator");
const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");

const connectDB = require("./db");
const User = require("./models/User");

const app = express();

const SECRET_KEY = process.env.SECRET_KEY;
const PORT = process.env.PORT || 3000;

/* ---------------- EMAIL ---------------- */
const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: "yourgmail@gmail.com",
        pass: "your_app_password"
    }
});

/* ---------------- MIDDLEWARE ---------------- */
app.use(cors({ origin: "*" }));
app.use(express.json());

/* ---------------- DB INIT (SAFE) ---------------- */
(async () => {
    try {
        await connectDB();
        console.log("🐺 MongoDB connected");
    } catch (err) {
        console.error("❌ DB connection failed:", err.message);
    }
})();

/* ---------------- ERROR HANDLERS ---------------- */
process.on("uncaughtException", (err) => {
    console.error("🔥 UNCAUGHT ERROR:", err);
});

process.on("unhandledRejection", (err) => {
    console.error("🔥 PROMISE ERROR:", err);
});

/* ---------------- ROUTES ---------------- */

app.get("/", (req, res) => {
    res.send("🐺 WolfCore Backend Running");
});

app.get("/test", (req, res) => {
    res.json({ message: "backend alive" });
});

/* ---------------- AUTH MIDDLEWARE ---------------- */
function verifyToken(req, res, next) {
    try {
        const authHeader = req.headers["authorization"];
        if (!authHeader) {
            return res.status(401).json({ message: "No token provided" });
        }

        const token = authHeader.split(" ")[1];

        jwt.verify(token, SECRET_KEY, (err, decoded) => {
            if (err) {
                return res.status(403).json({ message: "Invalid token" });
            }
            req.user = decoded;
            next();
        });

    } catch (err) {
        return res.status(500).json({ message: "Auth error" });
    }
}

/* ---------------- SIGNUP (OPTIMIZED) ---------------- */
app.post("/signup", async (req, res) => {
    try {
        const { username, email, password } = req.body;

        if (!username || !email || !password) {
            return res.status(400).json({ message: "All fields required" });
        }

        const contact = String(email).trim();

        const isEmail = validator.isEmail(contact);
        const isPhone = validator.isMobilePhone(contact, "any");

        if (!isEmail && !isPhone) {
            return res.status(400).json({ message: "Invalid email or phone" });
        }

        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ message: "Username exists" });
        }

        const existingContact = await User.findOne({ email: contact });
        if (existingContact) {
            return res.status(400).json({ message: "Email/phone used" });
        }

        if (password.length < 8) {
            return res.status(400).json({ message: "Password too short" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = new User({
            username,
            email: contact,
            password: hashedPassword,
            role: "user",
            progress: 0
        });

        await newUser.save();

        res.json({ message: "User created successfully" });

    } catch (err) {
        console.error("SIGNUP ERROR:", err);
        res.status(500).json({ message: "Server error" });
    }
});

/* ---------------- LOGIN (FAST VERSION) ---------------- */
app.post("/login", async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ message: "Missing fields" });
        }

        const user = await User.findOne({ username });

        if (!user) {
            return res.status(400).json({ message: "User not found" });
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(400).json({ message: "Wrong password" });
        }

        const token = jwt.sign(
            {
                id: user._id,
                username: user.username,
                role: user.role
            },
            SECRET_KEY,
            { expiresIn: "1h" }
        );

        res.json({
            message: "Login successful",
            token
        });

    } catch (err) {
        console.error("LOGIN ERROR:", err);
        res.status(500).json({ message: "Server error" });
    }
});

/* ---------------- DASHBOARD (OPTIMIZED) ---------------- */
app.get("/dashboard-data", verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id)
            .select("username email role progress")
            .lean();

        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        res.json({
            message: "Welcome 🐺",
            user
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Dashboard error" });
    }
});

/* ---------------- RESET FLOW ---------------- */

app.post("/request-reset", async (req, res) => {
    try {
        const { contact } = req.body;

        const user = await User.findOne({
            $or: [{ email: contact }, { username: contact }]
        });

        if (!user) {
            return res.status(400).json({ message: "User not found" });
        }

        const code = Math.floor(100000 + Math.random() * 900000).toString();

        user.resetCode = code;
        user.resetCodeExpiry = Date.now() + 10 * 60 * 1000;

        await user.save();

        if (user.email && user.email.includes("@")) {
            await transporter.sendMail({
                from: "WolfCore <yourgmail@gmail.com>",
                to: user.email,
                subject: "Reset Code",
                text: `Your code is: ${code}`
            });
        } else {
            console.log("RESET CODE:", code);
        }

        res.json({ message: "Reset code sent" });

    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error" });
    }
});

app.post("/reset-password", async (req, res) => {
    try {
        const { contact, code, newPassword } = req.body;

        const user = await User.findOne({
            $or: [{ email: contact }, { username: contact }]
        });

        if (!user) return res.status(400).json({ message: "User not found" });

        if (user.resetCode !== code) {
            return res.status(400).json({ message: "Invalid code" });
        }

        if (Date.now() > user.resetCodeExpiry) {
            return res.status(400).json({ message: "Code expired" });
        }

        if (newPassword.length < 8) {
            return res.status(400).json({ message: "Too short" });
        }

        user.password = await bcrypt.hash(newPassword, 10);
        user.resetCode = undefined;
        user.resetCodeExpiry = undefined;

        await user.save();

        res.json({ message: "Password reset successful" });

    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error" });
    }
});

/* ---------------- START SERVER ---------------- */
app.listen(PORT, () => {
    console.log(`🐺 WolfCore running on http://localhost:${PORT}`);
});