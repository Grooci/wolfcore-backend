const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
    username: { type: String, unique: true },
    email: { type: String, unique: true },
    password: String,
    role: { type: String, default: "user" },
    progress: { type: Number, default: 0 },

    resetCode: String,
    resetCodeExpiry: Date
});

module.exports = mongoose.model("User", userSchema);
