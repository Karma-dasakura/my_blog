require("dotenv").config();

const express = require("express");
const cookieParser = require("cookie-parser");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");
const { pool } = require("./src/db");
const { logger } = require("./src/logger");
const { errorHandler, requireCsrf, setCsrfCookie } = require("./src/security");
const authRoutes = require("./src/routes/auth");
const postRoutes = require("./src/routes/posts");

const required = ["DATABASE_URL", "JWT_SECRET", "DATA_ENCRYPTION_KEY"];
const missing = required.filter(
  (key) => !process.env[key] || process.env[key].includes("REPLACE_"),
);
if (missing.length) {
  throw new Error(
    `Missing required environment variables: ${missing.join(", ")}`
  );
}
if (!/^[a-fA-F0-9]{64}$/.test(process.env.DATA_ENCRYPTION_KEY)) {
  throw new Error(
    "DATA_ENCRYPTION_KEY must be exactly 64 hexadecimal characters (AES-256 key)."
  );
}

const app = express();
app.set("trust proxy", 1);
app.disable("x-powered-by");

// Helmet Security Headers
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'"],
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", "data:"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        frameAncestors: ["'none'"],
      },
    },
    hsts:
      process.env.NODE_ENV === "production"
        ? { maxAge: 31536000, includeSubDomains: true, preload: true }
        : false,
    referrerPolicy: { policy: "no-referrer" },
  })
);

app.use(express.json({ limit: "100kb" }));
app.use(cookieParser());

// 1. GENERATE CSRF COOKIE FOR ALL USERS
app.use(setCsrfCookie);

// 2. RATE LIMITING (Only in production so you don't lock yourself out locally)
if (process.env.NODE_ENV === "production") {
  app.use(
    "/api",
    rateLimit({
      windowMs: 15 * 60 * 1000,
      limit: 300,
      standardHeaders: true,
      legacyHeaders: false,
      handler: (_req, res) =>
        res.status(429).json({ error: "Too many requests. Please try again later." }),
    })
  );
  app.use(
    "/api/auth",
    rateLimit({
      windowMs: 15 * 60 * 1000,
      limit: 20,
      standardHeaders: true,
      legacyHeaders: false,
    })
  );
}

// 3. PUBLIC API ROUTES (No CSRF required)
app.get("/api/health", async (_req, res, next) => {
  try {
    await pool.query("SELECT 1");
    res.json({ status: "ok" });
  } catch (error) {
    next(error);
  }
});
app.get("/api/csrf", (_req, res) => res.json({ message: "Security token ready." }));

// 4. CSRF PROTECTION FOR ALL SUBSEQUENT API ROUTES
app.use("/api", requireCsrf);

// 5. PROTECTED API ROUTES
app.use("/api/auth", authRoutes);
app.use("/api/posts", postRoutes);

// 6. STATIC FRONTEND FILES
app.use(
  express.static(path.join(__dirname, "public"), {
    extensions: ["html"],
    maxAge: process.env.NODE_ENV === "production" ? "1h" : 0,
  })
);

// 7. 404 & ERROR HANDLERS
app.use((_req, res) => res.status(404).json({ error: "Resource not found." }));
app.use(errorHandler);

// 8. START SERVER
const port = Number(process.env.PORT || 3000);
const server = app.listen(port, () => {
  logger.info("Server started", {
    port,
    environment: process.env.NODE_ENV || "development",
  });
});

const shutdown = async () => {
  logger.info("Shutting down");
  server.close(async () => {
    await pool.end();
    process.exit(0);
  });
};
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);