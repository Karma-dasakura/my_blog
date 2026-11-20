const { Pool } = require("pg");
const fs = require("fs");
const path = require("path");
const { logger } = require("./logger");

const caCert = fs.readFileSync(path.join(__dirname, "prod-ca-2021.crt")).toString();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: true, // Enforce strict TLS verification
    ca: caCert,               // Trust the Supabase Root CA
  },
  max: 10,
  idleTimeoutMillis: 30000,
});
pool.on("error", (error) =>
  logger.error("Unexpected database pool error", { message: error.message }),
);
module.exports = { pool };