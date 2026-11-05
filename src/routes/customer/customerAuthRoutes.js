const express = require("express");
const router = express.Router();
const pool = require("../../config/db");
const jwt = require("jsonwebtoken");
require("dotenv").config();

/**
 * @swagger
 * tags:
 *   name: 3. Customer Panel (پنل مشتریان و سفارشات)
 *   description: احراز هویت مشتریان منوی دیجیتال از طریق کد تایید OTP
 */

/**
 * @swagger
 * /api/customer/auth/send-otp:
 *   post:
 *     summary: ارسال کد تایید OTP و تشخیص کاربر جدید یا قدیمی
 *     tags: [3. Customer Panel (پنل مشتریان و سفارشات)]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - phone_number
 *             properties:
 *               phone_number:
 *                 type: string
 *                 example: "09123456789"
 *     responses:
 *       200:
 *         description: کد تایید ارسال شد و وضعیت کاربر مشخص گردید
 */
router.post("/send-otp", async (req, res) => {
  try {
    const { phone_number } = req.body;

    if (!phone_number) {
      return res
        .status(400)
        .json({ error: "وارد کردن شماره همراه الزامی است." });
    }

    const otpCode = Math.floor(1000 + Math.random() * 9000).toString();
    const otpExpiresAt = new Date(Date.now() + 2 * 60 * 1000); // اعتبار ۲ دقیقه

    const existing = await pool.query(
      "SELECT * FROM customers WHERE phone_number = $1",
      [phone_number],
    );

    let isNewUser = true;

    if (existing.rows.length === 0) {
      // کاربر کلاً وجود ندارد -> پس قطعا جدید است
      await pool.query(
        `INSERT INTO customers (phone_number, otp_code, otp_expires_at, created_at) 
         VALUES ($1, $2, $3, NOW())`,
        [phone_number, otpCode, otpExpiresAt],
      );
    } else {
      // کاربر وجود دارد. بررسی می‌کنیم آیا نام و نام خانوادگی دارد یا خیر
      const customer = existing.rows[0];
      if (customer.first_name && customer.last_name) {
        isNewUser = false; // کاربر قدیمی است
      }

      await pool.query(
        `UPDATE customers SET otp_code = $1, otp_expires_at = $2 WHERE phone_number = $3`,
        [otpCode, otpExpiresAt, phone_number],
      );
    }

    console.log(`🔑 OTP Code for ${phone_number}: ${otpCode}`);

    res.json({
      message: "کد تایید با موفقیت ارسال شد.",
      is_new_user: isNewUser, // مشخص می‌کند فرانت‌اند باید فیلد نام را نمایش دهد یا خیر
      debug_otp: otpCode,
    });
  } catch (err) {
    console.error("Send OTP error:", err);
    res
      .status(500)
      .json({ error: "خطای داخلی سرور در ارسال کد تایید رخ داد." });
  }
});

/**
 * @swagger
 * /api/customer/auth/verify-otp:
 *   post:
 *     summary: تایید کد OTP، ثبت‌نام و ورود نهایی مشتری
 *     tags: [3. Customer Panel (پنل مشتریان و سفارشات)]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - phone_number
 *               - otp_code
 *             properties:
 *               phone_number:
 *                 type: string
 *                 example: "09123456789"
 *               otp_code:
 *                 type: string
 *                 example: "1234"
 *               first_name:
 *                 type: string
 *                 example: "علی"
 *               last_name:
 *                 type: string
 *                 example: "رضایی"
 *     responses:
 *       200:
 *         description: تایید موفقیت‌آمیز و صدور توکن
 */
router.post("/verify-otp", async (req, res) => {
  try {
    const { phone_number, otp_code, first_name, last_name } = req.body;

    if (!phone_number || !otp_code) {
      return res
        .status(400)
        .json({ error: "شماره همراه و کد تایید الزامی هستند." });
    }

    const result = await pool.query(
      "SELECT * FROM customers WHERE phone_number = $1",
      [phone_number],
    );

    if (result.rows.length === 0) {
      return res.status(400).json({
        error:
          "کاربری با این شماره همراه یافت نشد. لطفاً مجدداً درخواست کد کنید.",
      });
    }

    const customer = result.rows[0];

    // بررسی صحت کد OTP
    if (customer.otp_code !== otp_code) {
      return res.status(400).json({ error: "کد تایید وارد شده نادرست است." });
    }

    // بررسی انقضای کد OTP
    if (new Date() > new Date(customer.otp_expires_at)) {
      return res.status(400).json({
        error: "کد تایید منقضی شده است. لطفاً مجدداً درخواست کد کنید.",
      });
    }

    // بررسی اینکه آیا کاربر جدید است و نام/نام خانوادگی ندارد؟
    const isNewUser = !customer.first_name || !customer.last_name;

    if (isNewUser && (!first_name || !last_name)) {
      return res.status(400).json({
        error: "لطفاً برای تکمیل ثبت‌نام، نام و نام خانوادگی خود را وارد کنید.",
      });
    }

    // به‌روزرسانی اطلاعات، ثبت نام و پاک کردن کد OTP مصرف‌شده
    const updateRes = await pool.query(
      `UPDATE customers 
       SET first_name = COALESCE($1, first_name), 
           last_name = COALESCE($2, last_name), 
           otp_code = NULL, 
           otp_expires_at = NULL 
       WHERE phone_number = $3 
       RETURNING id, first_name, last_name, phone_number, created_at`,
      [first_name || null, last_name || null, phone_number],
    );

    const updatedCustomer = updateRes.rows[0];

    // صدور توکن JWT با اعتبار ۳۰ روزه
    const token = jwt.sign(
      {
        id: updatedCustomer.id,
        phone_number: updatedCustomer.phone_number,
        role: "customer",
      },
      process.env.JWT_SECRET,
      { expiresIn: "30d" },
    );

    res.json({
      message: "احراز هویت با موفقیت انجام شد و وارد حساب خود شدید.",
      token,
      customer: {
        id: updatedCustomer.id,
        first_name: updatedCustomer.first_name,
        last_name: updatedCustomer.last_name,
        phone_number: updatedCustomer.phone_number,
      },
    });
  } catch (err) {
    console.error("Verify OTP error:", err);
    res.status(500).json({ error: "خطای داخلی سرور در تایید کد OTP رخ داد." });
  }
});

module.exports = router;
