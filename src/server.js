const express = require("express");
const cors = require("cors");
require("dotenv").config();

const app = express();

// میدلورهای عمومی
app.use(express.json());
app.use(cors());

// ۱. ایمپورت روت‌های پنل مدیر کل پلتفرم (CRM Super Admin)
const adminAuthRoutes = require("./routes/admin/authRoutes");
const userRoutes = require("./routes/admin/userRoutes");

// ۲. ایمپورت روت‌های پنل بیزینس و مدیریت پرسنل (Business Panel)
const businessAuthRoutes = require("./routes/business/businessAuthRoutes");
const businessProfileRoutes = require("./routes/business/businessProfileRoutes");
const staffRoutes = require("./routes/business/staffRoutes");

// ۳. ایمپورت روت‌های پنل مشتریان (Customer Panel)
const customerAuthRoutes = require("./routes/customer/customerAuthRoutes");

// ایمپورت تنظیمات سوگر
const swaggerDocs = require("./swagger");

const PORT = process.env.PORT || 5000;

// ==========================================
// مسیرها (Routes)
// ==========================================

// ۱. روت‌های پنل مدیر کل پلتفرم (CRM Super Admin)
app.use("/api/admin/auth", adminAuthRoutes);
app.use("/api/admin/users", userRoutes);

// ۲. روت‌های پنل بیزینس و پرسنل کافه/رستوران (Business Panel)
app.use("/api/business/auth", businessAuthRoutes);
app.use("/api/business", businessProfileRoutes);
app.use("/api/business/staff", staffRoutes);

// ۳. روت‌های پنل مشتریان (Customer Panel)
app.use("/api/customer/auth", customerAuthRoutes);

// راه‌اندازی مستندات سوگر
swaggerDocs(app);

app.listen(PORT, () => {
  console.log(`Enterprise Server is running on port ${PORT}`);
});
