const express = require("express");
const router = express.Router();
const pool = require("../../config/db");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const verifyBusinessToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token)
    return res.status(401).json({ error: "توکن احراز هویت یافت نشد." });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err)
      return res.status(403).json({ error: "توکن منقضی شده یا معتبر نیست." });
    req.businessEmail = user.email;
    next();
  });
};

/**
 * @swagger
 * tags:
 *   name: 2. Business Panel (پنل صاحبان کافه و رستوران)
 *   description: مدیریت پروفایل بیزینس و پرسنل کافه/رستوران
 */

/**
 * @swagger
 * /api/business/profile:
 *   get:
 *     summary: دریافت اطلاعات پروفایل بیزینس
 *     tags: [2. Business Panel (پنل صاحبان کافه و رستوران)]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: دریافت موفق
 */
router.get("/profile", verifyBusinessToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, first_name, last_name, business_name, phone_number, address, 
              postal_code, business_address, business_postal_code, birth_date, 
              national_code, email, join_date, subscribed_plane, 
              remaining_subscription_days, plan_features, role 
       FROM businesses WHERE email = $1`,
      [req.businessEmail],
    );

    if (result.rows.length === 0) {
      return res
        .status(404)
        .json({ error: "اطلاعات پروفایل بیزینس یافت نشد." });
    }

    res.json({ business: result.rows[0] });
  } catch (err) {
    console.error("Get profile error:", err);
    res.status(500).json({ error: "خطای سرور در دریافت اطلاعات پروفایل." });
  }
});

/**
 * @swagger
 * /api/business/profile:
 *   post:
 *     summary: ثبت یا ویرایش اطلاعات پروفایل بیزینس
 *     tags: [2. Business Panel (پنل صاحبان کافه و رستوران)]
 *     security:
 *       - BearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               first_name:
 *                 type: string
 *               last_name:
 *                 type: string
 *               business_name:
 *                 type: string
 *               address:
 *                 type: string
 *               postal_code:
 *                 type: string
 *               business_address:
 *                 type: string
 *               business_postal_code:
 *                 type: string
 *               birth_date:
 *                 type: string
 *                 format: date
 *               national_code:
 *                 type: string
 *               phone_number:
 *                 type: string
 *     responses:
 *       200:
 *         description: بروزرسانی موفق
 */
router.post("/profile", verifyBusinessToken, async (req, res) => {
  try {
    const {
      first_name,
      last_name,
      business_name,
      address,
      postal_code,
      business_address,
      business_postal_code,
      birth_date,
      national_code,
      phone_number,
    } = req.body;

    const updateQuery = `
      UPDATE businesses 
      SET first_name = COALESCE($1, first_name),
          last_name = COALESCE($2, last_name),
          business_name = COALESCE($3, business_name),
          address = COALESCE($4, address),
          postal_code = COALESCE($5, postal_code),
          business_address = COALESCE($6, business_address),
          business_postal_code = COALESCE($7, business_postal_code),
          birth_date = COALESCE($8, birth_date),
          national_code = COALESCE($9, national_code),
          phone_number = COALESCE($10, phone_number)
      WHERE email = $11
      RETURNING id, first_name, last_name, business_name, phone_number, address, 
                postal_code, business_address, business_postal_code, birth_date, 
                national_code, email, join_date, subscribed_plane, 
                remaining_subscription_days, plan_features, role;
    `;

    const values = [
      first_name,
      last_name,
      business_name,
      address,
      postal_code,
      business_address,
      business_postal_code,
      birth_date,
      national_code,
      phone_number,
      req.businessEmail,
    ];

    const updated = await pool.query(updateQuery, values);

    if (updated.rows.length === 0) {
      return res.status(404).json({ error: "حساب کاربری بیزینس یافت نشد." });
    }

    res.json({
      message: "اطلاعات پروفایل کسب‌وکار با موفقیت به‌روزرسانی شد.",
      business: updated.rows[0],
    });
  } catch (err) {
    console.error("Update profile error:", err);
    res
      .status(500)
      .json({ error: "خطای سرور در به‌روزرسانی اطلاعات پروفایل." });
  }
});

module.exports = router;
