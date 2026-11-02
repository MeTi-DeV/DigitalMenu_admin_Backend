const bcrypt = require("bcryptjs");
const pool = require("../config/db");

// ایجاد کاربر / پرسنل جدید
const createUser = async (req, res) => {
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
      return res
        .status(400)
        .json({
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
};

// دریافت لیست تمام پرسنل
const getAllUsers = async (req, res) => {
  try {
    const users = await pool.query(
      "SELECT id, first_name, last_name, email, personnel_code, username, role, join_date FROM users ORDER BY id DESC",
    );
    res.json({ users: users.rows });
  } catch (err) {
    console.error("Get users error:", err);
    res.status(500).json({ error: "خطا در دریافت لیست پرسنل." });
  }
};

// حتماً هر دو تابع باید اینجا اکسپورت شوند
module.exports = {
  createUser,
  getAllUsers,
};
