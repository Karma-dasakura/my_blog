const router = require("express").Router();
const bcrypt = require("bcrypt");
const { pool } = require("../db");
const { encrypt, emailLookup } = require("../crypto");
const { email, password, text, positiveInt } = require("../validate");
const { authenticate, authorize, issueSession, cookieOptions } = require("../security");

router.post("/register", async (req, res, next) => {
  try {
    const name = text(req.body.name, "Name", { min: 2, max: 80 });
    const cleanEmail = email(req.body.email);
    const cleanPassword = password(req.body.password);
    const result = await pool.query(
      "INSERT INTO users (display_name, email_lookup, email_encrypted, password_hash) VALUES ($1, $2, $3, $4) RETURNING id, role",
      [
        name,
        emailLookup(cleanEmail),
        encrypt(cleanEmail),
        await bcrypt.hash(cleanPassword, 12),
      ],
    );
    issueSession(res, result.rows[0]);
    res
      .status(201)
      .json({
        message: "Account created.",
        user: { id: result.rows[0].id, name, role: result.rows[0].role },
      });
  } catch (error) {
    if (error.code === "23505") {
      error.status = 409;
      error.message = "An account with that email already exists.";
    }
    next(error);
  }
});
router.post("/login", async (req, res, next) => {
  try {
    const cleanEmail = email(req.body.email);
    const suppliedPassword = text(req.body.password, "Password", {
      min: 1,
      max: 128,
    });
    const result = await pool.query(
      "SELECT id, display_name, role, password_hash FROM users WHERE email_lookup = $1",
      [emailLookup(cleanEmail)],
    );
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(suppliedPassword, user.password_hash)))
      return res.status(401).json({ error: "Invalid email or password." });
    issueSession(res, user);
    res.json({
      message: "Logged in.",
      user: { id: user.id, name: user.display_name, role: user.role },
    });
  } catch (error) {
    next(error);
  }
});
router.post("/logout", (_req, res) => {
  res.clearCookie("session", cookieOptions);
  res.json({ message: "Logged out." });
});
router.get("/me", authenticate, async (req, res, next) => {
  try {
    const result = await pool.query(
      "SELECT id, display_name AS name, role FROM users WHERE id = $1",
      [req.user.id],
    );
    res.json({ user: result.rows[0] });
  } catch (error) {
    next(error);
  }
});

// Admin route to delete a user
router.delete("/admin/users/:id", authenticate, authorize("admin"), async (req, res, next) => {
  try {
    const userId = positiveInt(req.params.id, "User ID");
    
    // Prevent admin from deleting themselves
    if (userId === req.user.id) {
      return res.status(400).json({ error: "You cannot delete your own admin account." });
    }

    const result = await pool.query("DELETE FROM users WHERE id = $1 RETURNING id", [userId]);
    if (!result.rows[0]) return res.status(404).json({ error: "User not found." });
    
    res.json({ message: "User deleted successfully." });
  } catch (error) {
    next(error);
  }
});

module.exports = router;
