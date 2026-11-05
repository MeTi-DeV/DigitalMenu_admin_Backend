const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const pool = require("../../config/db");
const jwt = require("jsonwebtoken");
require("dotenv").config();

/**
 * @swagger
 * tags:
 *   name: 2. Business Panel (پنل صاحبان کافه و رستوران)
 *   description: مدیریت احراز هویت صاحبان کسب‌وکار و مدیران
 */

/**
 * @swagger
 * /api/business/auth/register:
 *   post:
 *     summary: ثبت‌نام مدیر کل / صاحب کسب‌وکار اولیه
 *     tags: [2. Business Panel (پنل صاحبان کافه و رستوران)]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - first_name
 *               - last_name
 *               - email
 *               - password
 *             properties:
 *               first_name:
 *                 type: string
 *               last_name:
 *                 type: string
 *               address:
 *                 type: string
 *               birth_date:
 *                 type: string
 *                 format: date
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *               national_code:
 *                 type: string
 *               phone_number:
 *                 type: string
 *     responses:
 *       201:
 *         description: ثبت‌نام مدیر با موفقیت انجام شد
 */
router.post("/register", async (req, res) => {
  try {
    const {
      first_name,
      last_name,
      address,
      birth_date,
      email,
      password,
      national_code,
      phone_number,
    } = req.body;

    if (!email || !password || !first_name || !last_name) {
      return res.status(400).json({
        error:
          "لطفاً فیلدهای اجباری (نام، نام خانوادگی، ایمیل و رمز عبور) را کامل کنید.",
      });
    }

    const existingUser = await pool.query(
      "SELECT * FROM businesses WHERE email = $1",
      [email],
    );
    if (existingUser.rows.length > 0) {
      return res
        .status(400)
        .json({
          error: "کاربری با این ایمیل قبلاً در سیستم ثبت‌نام کرده است.",
        });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // اولین کاربری که در جدول businesses ثبت‌نام می‌کند به عنوان مدیر کل (manager) شناخته می‌شود
    const checkCount = await pool.query("SELECT COUNT(*) FROM businesses");
    const isFirstManager = parseInt(checkCount.rows[0].count) === 0;
    const assignedRole = isFirstManager ? "manager" : "business";

    const newBusiness = await pool.query(
      `INSERT INTO businesses (
        first_name, last_name, address, birth_date, email, password, national_code, phone_number, role, join_date
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW()) 
      RETURNING id, first_name, last_name, email, role, phone_number`,
      [
        first_name,
        last_name,
        address,
        birth_date,
        email,
        hashedPassword,
        national_code,
        phone_number,
        assignedRole,
      ],
    );

    res.status(201).json({
      message: "حساب کاربری مدیریت کسب‌وکار با موفقیت ایجاد شد.",
      business: newBusiness.rows[0],
    });
  } catch (err) {
    console.error("Register error:", err);
    res
      .status(500)
      .json({ error: "خطای داخلی سرور در عملیات ثبت‌نام رخ داد." });
  }
});

/**
 * @swagger
 * /api/business/auth/login:
 *   post:
 *     summary: ورود صاحب کسب‌وکار / مدیر بیزینس با ایمیل و پسورد
 *     tags: [2. Business Panel (پنل صاحبان کافه و رستوران)]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: ورود موفق
 */
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res
        .status(400)
        .json({ error: "وارد کردن ایمیل و رمز عبور الزامی است." });
    }

    const result = await pool.query(
      "SELECT * FROM businesses WHERE email = $1",
      [email],
    );
    if (result.rows.length === 0) {
      return res
        .status(400)
        .json({ error: "ایمیل یا رمز عبور وارد شده نادرست است." });
    }

    const user = result.rows[0];

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res
        .status(400)
        .json({ error: "ایمیل یا رمز عبور وارد شده نادرست است." });
    }

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        role: user.role,
        business_name: user.business_name,
      },
      process.env.JWT_SECRET,
      { expiresIn: "7d" },
    );

    await pool.query("UPDATE businesses SET login_token = $1 WHERE id = $2", [
      token,
      user.id,
    ]);

    res.json({
      message: "با موفقیت به پنل مدیریت کسب‌وکار وارد شدید.",
      token,
      user: {
        id: user.id,
        first_name: user.first_name,
        last_name: user.last_name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "خطای داخلی سرور در عملیات ورود رخ داد." });
  }
});

module.exports = router;
