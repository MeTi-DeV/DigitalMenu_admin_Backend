const swaggerJsdoc = require("swagger-jsdoc");
const swaggerUi = require("swagger-ui-express");

const options = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "Digital Menu CRM API",
      version: "1.0.0",
      description: "مستندات APIهای پنل مدیریت و پرسنل پلتفرم منوی دیجیتال",
    },
    servers: [
      {
        url: "http://localhost:3000",
        description: "سرور توسعه (Local Development)",
      },
    ],
    components: {
      securitySchemes: {
        BearerAuth: {
          type: "http",
          scheme: "bearer",
          bearerFormat: "JWT",
          description: "توکن احراز هویت را به صورت Bearer <token> وارد کنید",
        },
      },
    },
  },
  // 👈 با استفاده از ** تمام فایل‌های داخل زیرپوشه‌ها (admin و business) به طور خودکار اسکن می‌شوند
  apis: ["./src/routes/**/*.js"],
};

const specs = swaggerJsdoc(options);

const swaggerDocs = (app) => {
  app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(specs));
  console.log("📄 Swagger Docs available at http://localhost:3000/api-docs");
};

module.exports = swaggerDocs;
