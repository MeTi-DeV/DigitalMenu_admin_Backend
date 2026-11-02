const express = require("express");
const cors = require("cors");
require("dotenv").config();

const authRoutes = require("./routes/authRoutes");
const userRoutes = require("./routes/userRoutes");
const swaggerDocs = require("./swagger"); // چون swagger.js در همین پوشه src است

const app = express();
app.use(express.json());
app.use(cors());

const PORT = process.env.PORT || 5000;

// مسیرها (Routes)
app.use("/api/auth", authRoutes);
app.use("/api/admin/users", userRoutes);

// راه‌اندازی مستندات سوگر
swaggerDocs(app);

app.listen(PORT, () => {
  console.log(`Enterprise Server is running on port ${PORT}`);
});
