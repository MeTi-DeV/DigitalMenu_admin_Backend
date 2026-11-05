const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const pool = require("../../config/db");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const verifyManagerToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token)
    return res
      .status(401)
      .json({ error: "توکن احراز هویت یافت نشد. لطفا وارد شوید." });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err)
      return res
        .status(403)
        .json({ error: "توکن نامعتبر است یا اعتبار آن به پایان رسیده است." });
    if (user.role !== "manager") {
      return res
        .status(403)
        .json({
          error:
            "شما مجوز لازم برای انجام این عملیات را ندارید. فقط مدیر مجموعه دسترسی دارد.",
        });
    }
    req.user = user;
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
 * /api/business/staff/register:
 *   post:
 *     summary: ثبت‌نام اولیه کارمند جدید (منتظر تایید مدیر)
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
 *         description: درخواست ثبت‌نام با موفقیت ثبت شد
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
      return res
        .status(400)
        .json({
          error:
            "لطفاً فیلدهای اجباری (نام، نام خانوادگی، ایمیل و رمز عبور) را کامل کنید.",
        });
    }

    const existing = await pool.query("SELECT * FROM staff WHERE email = $1", [
      email,
    ]);
    if (existing.rows.length > 0) {
      return res
        .status(400)
        .json({
          error: "کاربری با این ایمیل قبلاً در سیستم ثبت‌نام کرده است.",
        });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newStaff = await pool.query(
      `INSERT INTO staff (
        first_name, last_name, address, birth_date, email, password, national_code, phone_number, role, status, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending', 'pending', NOW()) 
      RETURNING id, first_name, last_name, email, role, status, created_at`,
      [
        first_name,
        last_name,
        address,
        birth_date,
        email,
        hashedPassword,
        national_code,
        phone_number,
      ],
    );

    res.status(201).json({
      message:
        "ثبت‌نام شما با موفقیت انجام شد. پس از تأیید نهایی توسط مدیر مجموعه، دسترسی شما به پنل فعال خواهد شد.",
      staff: newStaff.rows[0],
    });
  } catch (err) {
    console.error("Staff register error:", err);
    res
      .status(500)
      .json({ error: "خطای داخلی سرور هنگام ثبت‌نام پرسنل رخ داد." });
  }
});

/**
 * @swagger
 * /api/business/staff/login:
 *   post:
 *     summary: ورود پرسنل (گارسون یا صندوق‌دار) با ایمیل و پسورد
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
 *                 example: "staff@restaurant.com"
 *               password:
 *                 type: string
 *                 example: "123456"
 *     responses:
 *       200:
 *         description: ورود موفقیت‌آمیز
 */
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res
        .status(400)
        .json({ error: "وارد کردن ایمیل و رمز عبور الزامی است." });
    }

    const result = await pool.query("SELECT * FROM staff WHERE email = $1", [
      email,
    ]);
    if (result.rows.length === 0) {
      return res
        .status(400)
        .json({ error: "ایمیل یا رمز عبور وارد شده نادرست است." });
    }

    const staffMember = result.rows[0];

    if (staffMember.status !== "approved") {
      return res.status(403).json({
        error: "حساب کاربری شما هنوز توسط مدیر مجموعه تایید نشده است.",
      });
    }

    const isMatch = await bcrypt.compare(password, staffMember.password);
    if (!isMatch) {
      return res
        .status(400)
        .json({ error: "ایمیل یا رمز عبور وارد شده نادرست است." });
    }

    const token = jwt.sign(
      {
        id: staffMember.id,
        email: staffMember.email,
        role: staffMember.role,
        work_start_time: staffMember.work_start_time,
        work_end_time: staffMember.work_end_time,
      },
      process.env.JWT_SECRET,
      { expiresIn: "7d" },
    );

    await pool.query("UPDATE staff SET login_token = $1 WHERE id = $2", [
      token,
      staffMember.id,
    ]);

    res.json({
      message: "با موفقیت وارد سیستم شدید.",
      token,
      staff: {
        id: staffMember.id,
        first_name: staffMember.first_name,
        last_name: staffMember.last_name,
        email: staffMember.email,
        role: staffMember.role,
        work_start_time: staffMember.work_start_time,
        work_end_time: staffMember.work_end_time,
      },
    });
  } catch (err) {
    console.error("Staff login error:", err);
    res
      .status(500)
      .json({ error: "خطای داخلی سرور در عملیات ورود پرسنل رخ داد." });
  }
});

/**
 * @swagger
 * /api/business/staff:
 *   get:
 *     summary: دریافت لیست تمام پرسنل مجموعه (فقط مدیر)
 *     tags: [2. Business Panel (پنل صاحبان کافه و رستوران)]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: لیست پرسنل
 */
router.get("/", verifyManagerToken, async (req, res) => {
  try {
    const staffList = await pool.query(
      `SELECT id, first_name, last_name, email, national_code, phone_number, address, birth_date, role, status, work_start_time, work_end_time, created_at FROM staff ORDER BY id DESC`,
    );
    res.json({ staff: staffList.rows });
  } catch (err) {
    console.error("Get staff list error:", err);
    res.status(500).json({ error: "خطا در دریافت لیست پرسنل مجموعه." });
  }
});

/**
 * @swagger
 * /api/business/staff/{id}:
 *   get:
 *     summary: دریافت اطلاعات یک کارمند به صورت تکی (فقط مدیر)
 *     tags: [2. Business Panel (پنل صاحبان کافه و رستوران)]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: شناسه کارمند
 *     responses:
 *       200:
 *         description: اطلاعات کارمند
 */
router.get("/:id", verifyManagerToken, async (req, res) => {
  try {
    const staffId = req.params.id;
    const staffMember = await pool.query(
      `SELECT id, first_name, last_name, email, national_code, phone_number, address, birth_date, role, status, work_start_time, work_end_time, created_at FROM staff WHERE id = $1`,
      [staffId],
    );

    if (staffMember.rows.length === 0) {
      return res.status(404).json({ error: "کارمندی با این مشخصات یافت نشد." });
    }

    res.json({ staff: staffMember.rows[0] });
  } catch (err) {
    console.error("Get single staff error:", err);
    res.status(500).json({ error: "خطا در دریافت اطلاعات کارمند." });
  }
});

/**
 * @swagger
 * /api/business/staff/{id}/approve:
 *   put:
 *     summary: تایید ثبت‌نام کارمند و تعیین نقش و ساعت شروع و پایان کار (توسط مدیر)
 *     tags: [2. Business Panel (پنل صاحبان کافه و رستوران)]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: شناسه کارمند
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - role
 *             properties:
 *               role:
 *                 type: string
 *                 enum: [cashier, waiter]
 *               work_start_time:
 *                 type: string
 *                 example: "08:00"
 *               work_end_time:
 *                 type: string
 *                 example: "16:00"
 *     responses:
 *       200:
 *         description: تایید موفق
 */
router.put("/:id/approve", verifyManagerToken, async (req, res) => {
  try {
    const staffId = req.params.id;
    const { role, work_start_time, work_end_time } = req.body;

    if (!["cashier", "waiter"].includes(role)) {
      return res.status(400).json({
        error:
          "نقش انتخاب شده نامعتبر است. مقادیر مجاز: cashier (صندوق‌دار) یا waiter (گارسون)",
      });
    }

    const updated = await pool.query(
      `UPDATE staff 
       SET role = $1, 
           status = 'approved', 
           work_start_time = COALESCE($2, work_start_time), 
           work_end_time = COALESCE($3, work_end_time) 
       WHERE id = $4 
       RETURNING id, first_name, last_name, email, role, status, work_start_time, work_end_time`,
      [role, work_start_time, work_end_time, staffId],
    );

    if (updated.rows.length === 0) {
      return res
        .status(404)
        .json({ error: "کارمند مورد نظر برای تایید یافت نشد." });
    }

    res.json({
      message: "حساب کاربری کارمند با موفقیت تایید و شیفت کاری‌اش ثبت شد.",
      staff: updated.rows[0],
    });
  } catch (err) {
    console.error("Approve staff error:", err);
    res.status(500).json({ error: "خطای سرور در تایید اطلاعات کارمند." });
  }
});

/**
 * @swagger
 * /api/business/staff/{id}:
 *   put:
 *     summary: ویرایش اطلاعات، نقش یا ساعت‌های کاری کارمند (توسط مدیر)
 *     tags: [2. Business Panel (پنل صاحبان کافه و رستوران)]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: شناسه کارمند
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
 *               address:
 *                 type: string
 *               birth_date:
 *                 type: string
 *                 format: date
 *               national_code:
 *                 type: string
 *               phone_number:
 *                 type: string
 *               role:
 *                 type: string
 *                 enum: [cashier, waiter, pending]
 *               work_start_time:
 *                 type: string
 *                 example: "08:00"
 *               work_end_time:
 *                 type: string
 *                 example: "16:00"
 *               status:
 *                 type: string
 *                 enum: [approved, pending, rejected]
 *     responses:
 *       200:
 *         description: بروزرسانی موفق
 */
router.put("/:id", verifyManagerToken, async (req, res) => {
  try {
    const staffId = req.params.id;
    const {
      first_name,
      last_name,
      address,
      birth_date,
      national_code,
      phone_number,
      role,
      work_start_time,
      work_end_time,
      status,
    } = req.body;

    const updateQuery = `
      UPDATE staff 
      SET first_name = COALESCE($1, first_name),
          last_name = COALESCE($2, last_name),
          address = COALESCE($3, address),
          birth_date = COALESCE($4, birth_date),
          national_code = COALESCE($5, national_code),
          phone_number = COALESCE($6, phone_number),
          role = COALESCE($7, role),
          work_start_time = COALESCE($8, work_start_time),
          work_end_time = COALESCE($9, work_end_time),
          status = COALESCE($10, status)
      WHERE id = $11
      RETURNING id, first_name, last_name, email, national_code, phone_number, address, birth_date, role, status, work_start_time, work_end_time;
    `;

    const values = [
      first_name,
      last_name,
      address,
      birth_date,
      national_code,
      phone_number,
      role,
      work_start_time,
      work_end_time,
      status,
      staffId,
    ];

    const updated = await pool.query(updateQuery, values);

    if (updated.rows.length === 0) {
      return res
        .status(404)
        .json({ error: "کارمند مورد نظر جهت ویرایش یافت نشد." });
    }

    res.json({
      message: "اطلاعات کارمند با موفقیت ویرایش و ذخیره شد.",
      staff: updated.rows[0],
    });
  } catch (err) {
    console.error("Update staff error:", err);
    res.status(500).json({ error: "خطای سرور در ویرایش اطلاعات کارمند." });
  }
});

/**
 * @swagger
 * /api/business/staff/{id}:
 *   delete:
 *     summary: حذف کارمند از مجموعه (توسط مدیر)
 *     tags: [2. Business Panel (پنل صاحبان کافه و رستوران)]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: شناسه کارمند
 *     responses:
 *       200:
 *         description: حذف موفق
 */
router.delete("/:id", verifyManagerToken, async (req, res) => {
  try {
    const staffId = req.params.id;
    const deleted = await pool.query(
      "DELETE FROM staff WHERE id = $1 RETURNING id, email",
      [staffId],
    );

    if (deleted.rows.length === 0) {
      return res
        .status(404)
        .json({ error: "کارمند مورد نظر برای حذف یافت نشد." });
    }

    res.json({
      message: "کارمند مورد نظر با موفقیت از سیستم حذف شد.",
      deleted_id: deleted.rows[0].id,
    });
  } catch (err) {
    console.error("Delete staff error:", err);
    res.status(500).json({ error: "خطای سرور در حذف کارمند." });
  }
});

module.exports = router;
