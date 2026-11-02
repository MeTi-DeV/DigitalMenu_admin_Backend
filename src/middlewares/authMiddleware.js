const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const pool = require("../config/db");
require("dotenv").config();

const login = async (req, res) => {
  try {
    const { username, password } = req.body; // ورود با username یا email

    const userResult = await pool.query(
      "SELECT * FROM users WHERE username = $1 OR email = $1",
      [username],
    );

    if (userResult.rows.length === 0) {
      return res
        .status(400)
        .json({ error: "نام کاربری یا کلمه عبور اشتباه است." });
    }

    const user = userResult.rows[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res
        .status(400)
        .json({ error: "نام کاربری یا کلمه عبور اشتباه است." });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1d" },
    );

    res.json({
      message: "ورود موفقیت‌آمیز بود.",
      token,
      user: {
        id: user.id,
        first_name: user.first_name,
        last_name: user.last_name,
        email: user.email,
        personnel_code: user.personnel_code,
        role: user.role,
      },
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "خطای سرور در هنگام ورود." });
  }
};

module.exports = { login };
