const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const pool = require("../../config/db");
require("dotenv").config();

/**
 * @swagger
 * tags:
 *   name: 1. CRM Super Admin (پنل مدیر کل پلتفرم)
 *   description: احراز هویت مدیر کل و ادمین‌های اصلی پلتفرم
 */

/**
 * @swagger
 * /api/admin/auth/login:
 *   post:
 *     summary: ورود به سیستم مدیران کل پلتفرم
 *     tags: [1. CRM Super Admin (پنل مدیر کل پلتفرم)]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - username
 *               - password
 *             properties:
 *               username:
 *                 type: string
 *                 example: "admin"
 *               password:
 *                 type: string
 *                 example: "123456"
 *     responses:
 *       200:
 *         description: ورود موفقیت‌آمیز
 */
router.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res
        .status(400)
        .json({ error: "وارد کردن نام کاربری و رمز عبور الزامی است." });
    }

    const userResult = await pool.query(
      "SELECT * FROM users WHERE username = $1 OR email = $1",
      [username],
    );

    if (userResult.rows.length === 0) {
      return res
        .status(400)
        .json({ error: "نام کاربری یا کلمه عبور وارد شده نادرست است." });
    }

    const user = userResult.rows[0];

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res
        .status(400)
        .json({ error: "نام کاربری یا کلمه عبور وارد شده نادرست است." });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1d" },
    );

    res.json({
      message: "با موفقیت به پنل مدیریت کل پلتفرم وارد شدید.",
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
    res.status(500).json({ error: "خطای داخلی سرور در عملیات ورود رخ داد." });
  }
});

module.exports = router;
