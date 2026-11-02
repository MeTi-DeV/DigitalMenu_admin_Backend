const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const pool = require("../config/db");
const jwt = require("jsonwebtoken");
require("dotenv").config();

// میدلور احراز هویت (فقط برای دریافت لیست پرسنل باقی می‌ماند)
const verifyToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ error: "توکن دسترسی موجود نیست." });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err)
      return res.status(403).json({ error: "توکن نامعتبر یا منقضی شده است." });
    req.user = user;
    next();
  });
};

const authorizeRoles = (...allowedRoles) => {
  return (req, res, next) => {
    if (!allowedRoles.includes(req.user.role)) {
      return res
        .status(403)
        .json({ error: "شما اجازه دسترسی به این بخش را ندارید." });
    }
    next();
  };
};

/**
 * @swagger
 * tags:
 *   name: Users & Personnel
 *   description: مدیریت پرسنل داخلی سامانه
 */

/**
 * @swagger
 * /api/admin/users:
 *   get:
 *     summary: دریافت لیست تمام پرسنل (نیاز به توکن)
 *     tags: [Users & Personnel]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: لیست پرسنل با موفقیت بازگردانده شد
 */
router.get(
  "/",
  verifyToken,
  authorizeRoles("boss", "admin"),
  async (req, res) => {
    try {
      const users = await pool.query(
        "SELECT id, first_name, last_name, email, personnel_code, username, role, join_date FROM users ORDER BY id DESC",
      );
      res.json({ users: users.rows });
    } catch (err) {
      console.error("Get users error:", err);
      res.status(500).json({ error: "خطا در دریافت لیست پرسنل." });
    }
  },
);

/**
 * @swagger
 * /api/admin/users:
 *   post:
 *     summary: ایجاد پرسنل جدید (بدون نیاز به توکن)
 *     tags: [Users & Personnel]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - first_name
 *               - last_name
 *               - father_name
 *               - national_code
 *               - birth_date
 *               - email
 *               - personnel_code
 *               - username
 *               - password
 *               - role
 *             properties:
 *               first_name:
 *                 type: string
 *               last_name:
 *                 type: string
 *               father_name:
 *                 type: string
 *               national_code:
 *                 type: string
 *               birth_date:
 *                 type: string
 *                 format: date
 *               email:
 *                 type: string
 *               personnel_code:
 *                 type: string
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *               role:
 *                 type: string
 *                 enum: [boss, admin, support]
 *     responses:
 *       201:
 *         description: پرسنل جدید با موفقیت ایجاد شد
 */
router.post("/", async (req, res) => {
  try {
    const {
      first_name,
      last_name,
      father_name,
      national_code,
      birth_date,
      email,
      personnel_code,
      username,
      password,
      role,
    } = req.body;

    if (!["boss", "admin", "support"].includes(role)) {
      return res.status(400).json({
        error: "نقش کاربر نامعتبر است. مقادیر مجاز: boss, admin, support",
      });
    }

    const duplicateCheck = await pool.query(
      "SELECT * FROM users WHERE email = $1 OR national_code = $2 OR username = $3 OR personnel_code = $4",
      [email, national_code, username, personnel_code],
    );

    if (duplicateCheck.rows.length > 0) {
      return res.status(400).json({
        error:
          "اطلاعات تکراری است. ایمیل، کد ملی، نام کاربری یا کد پرسنلی قبلاً ثبت شده است.",
      });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = await pool.query(
      `INSERT INTO users (
        first_name, last_name, father_name, national_code, birth_date, 
        email, personnel_code, join_date, username, password, role
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), $8, $9, $10) 
      RETURNING id, first_name, last_name, email, personnel_code, username, role, join_date`,
      [
        first_name,
        last_name,
        father_name,
        national_code,
        birth_date,
        email,
        personnel_code,
        username,
        hashedPassword,
        role,
      ],
    );

    res.status(201).json({
      message: "کارمند جدید با موفقیت ایجاد شد.",
      user: newUser.rows[0],
    });
  } catch (err) {
    console.error("Create user error:", err);
    res.status(500).json({ error: "خطای سرور در هنگام ثبت کاربر جدید." });
  }
});

module.exports = router;
