const express = require("express");
const router = express.Router();
const pool = require("../config/db");
const jwt = require("jsonwebtoken");
require("dotenv").config();

// حافظه موقت (Temporary Memory) برای نگهداری کدهای OTP در حال انتظار
// کلید: شماره موبایل، مقدار: { otp, expiresAt }
const otpStore = new Map();

/**
 * @swagger
 * tags:
 *   name: Customer Authentication
 *   description: احراز هویت مشتریان با شماره موبایل و OTP
 */

/**
 * @swagger
 * /api/customer/auth/send-otp:
 *   post:
 *     summary: ارسال کد تأیید (OTP) به شماره موبایل مشتری
 *     tags: [Customer Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - mobile
 *             properties:
 *               mobile:
 *                 type: string
 *                 example: "09123456789"
 *     responses:
 *       200:
 *         description: کد تأیید با موفقیت ارسال شد
 */
router.post("/send-otp", async (req, res) => {
  try {
    const { mobile } = req.body;

    if (!mobile || mobile.length < 10) {
      return res.status(400).json({ error: "شماره موبایل نامعتبر است." });
    }

    // تولید کد تصادفی ۴ رقمی
    const otpCode = Math.floor(1000 + Math.random() * 9000).toString();
    // انقضا پس از ۲ دقیقه
    const expiresAt = Date.now() + 2 * 60 * 1000;

    // ذخیره موقت OTP در حافظه سرور (بدون نشستن در دیتابیس)
    otpStore.set(mobile, { otp: otpCode, expiresAt });

    // شبیه‌سازی ارسال پیامک (چاپ در کنسول سرور)
    console.log(`📱 [SMS Gateway Simulator] OTP for ${mobile}: ${otpCode}`);

    res.json({
      message: "کد تأیید با موفقیت ارسال شد.",
      debug_otp: otpCode, // برای تست راحت‌تر در Postman/Swagger
    });
  } catch (err) {
    console.error("Send OTP error:", err);
    res.status(500).json({ error: "خطای سرور در ارسال کد تأیید." });
  }
});

/**
 * @swagger
 * /api/customer/auth/verify-otp:
 *   post:
 *     summary: بررسی کد تأیید، ثبت‌نام اولیه (در صورت نیاز) و ذخیره توکن در دیتابیس
 *     tags: [Customer Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - mobile
 *               - otp
 *             properties:
 *               mobile:
 *                 type: string
 *                 example: "09123456789"
 *               otp:
 *                 type: string
 *                 example: "1234"
 *     responses:
 *       200:
 *         description: ورود موفقیت‌آمیز و ذخیره توکن
 */
router.post("/verify-otp", async (req, res) => {
  try {
    const { mobile, otp } = req.body;

    if (!mobile || !otp) {
      return res.status(400).json({ error: "شماره موبایل و کد تأیید الزامی هستند." });
    }

    // بررسی وجود کد در حافظه موقت
    const storedData = otpStore.get(mobile);
    if (!storedData) {
      return res.status(400).json({ error: "کد تأیید نامعتبر است یا درخواستی ثبت نشده است." });
    }

    // بررسی انقضا
    if (Date.now() > storedData.expiresAt) {
      otpStore.delete(mobile);
      return res.status(400).json({ error: "کد تأیید منقضی شده است." });
    }

    // بررسی صحت کد
    if (storedData.otp !== otp) {
      return res.status(400).json({ error: "کد تأیید اشتباه است." });
    }

    // کد درست است؛ پاک کردن آن از حافظه موقت
    otpStore.delete(mobile);

    // تولید JWT Token
    // اول چک کنیم مشتری در دیتابیس هست یا نه
    let customerResult = await pool.query("SELECT * FROM customers WHERE mobile = $1", [mobile]);
    let customer;

    const token = jwt.sign(
      { mobile, role: "customer" },
      process.env.JWT_SECRET,
      { expiresIn: "30d" }
    );

    if (customerResult.rows.length === 0) {
      // اگر مشتری جدید بود، ایجاد رکورد جدید همراه با ذخیره توکن
      const newCustomer = await pool.query(
        "INSERT INTO customers (mobile, current_token) VALUES ($1, $2) RETURNING id, mobile, first_name, last_name, created_at",
        [mobile, token]
      );
      customer = newCustomer.rows[0];
    } else {
      // اگر مشتری از قبل بود، آپدیت کردن توکن جدید در دیتابیس
      const updatedCustomer = await pool.query(
        "UPDATE customers SET current_token = $1 WHERE mobile = $2 RETURNING id, mobile, first_name, last_name, created_at",
        [token, mobile]
      );
      customer = updatedCustomer.rows[0];
    }

    res.json({
      message: "ورود موفقیت‌آمیز بود.",
      token,
      customer: {
        id: customer.id,
        mobile: customer.mobile,
        first_name: customer.first_name,
        last_name: customer.last_name,
        role: "customer"
      },
    });
  } catch (err) {
    console.error("Verify OTP error:", err);
    res.status(500).json({ error: "خطای سرور در تأیید کد." });
  }
});

module.exports = router;