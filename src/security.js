const jwt = require("jsonwebtoken");
const { logger } = require("./logger");

const configuredHours = Number(process.env.SESSION_DURATION_HOURS || 168);
const sessionHours =
  Number.isFinite(configuredHours) &&
  configuredHours >= 1 &&
  configuredHours <= 720
    ? configuredHours
    : 168;
const isProduction = process.env.NODE_ENV === "production";
// Use 'lax' to ensure the cookie is sent when navigating between pages in development
const cookieOptions = {
  httpOnly: true,
  secure: isProduction,
  sameSite: "lax",
  path: "/",
  maxAge: sessionHours * 60 * 60 * 1000,
};
const csrfCookieOptions = {
  httpOnly: false,
  secure: isProduction,
  sameSite: "lax",
  path: "/",
  maxAge: sessionHours * 60 * 60 * 1000,
};
function setCsrfCookie(req, res, next) {
  if (!req.cookies.csrf_token)
    res.cookie(
      "csrf_token",
      require("crypto").randomBytes(32).toString("hex"),
      csrfCookieOptions,
    );
  next();
}
function requireCsrf(req, res, next) {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) return next();
  const cookieToken = req.cookies.csrf_token;
  const requestToken = req.get("x-csrf-token");
  if (
    !cookieToken ||
    !requestToken ||
    cookieToken.length !== requestToken.length
  )
    return res.status(403).json({
      error:
        "Security token missing or expired. Refresh the page and try again.",
    });
  const valid = require("crypto").timingSafeEqual(
    Buffer.from(cookieToken),
    Buffer.from(requestToken),
  );
  if (!valid)
    return res.status(403).json({
      error:
        "Security token missing or expired. Refresh the page and try again.",
    });
  next();
}
function authenticate(req, res, next) {
  try {
    req.user = jwt.verify(req.cookies.session, process.env.JWT_SECRET, {
      algorithms: ["HS256"],
    });
    next();
  } catch {
    return res.status(401).json({ error: "Please log in to continue." });
  }
}
function authorize(...roles) {
  return (req, res, next) =>
    roles.includes(req.user.role)
      ? next()
      : res
          .status(403)
          .json({ error: "You do not have permission for this action." });
}
function issueSession(res, user) {
  res.cookie(
    "session",
    jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, {
      algorithm: "HS256",
      expiresIn: `${sessionHours}h`,
      issuer: "ele201-myblog",
    }),
    cookieOptions,
  );
}
function errorHandler(error, req, res, _next) {
  const databaseConnectionError =
    ["ENOTFOUND", "ECONNREFUSED", "ETIMEDOUT", "ECONNRESET"].includes(
      error.code,
    ) || /certificate|database connection/i.test(error.message);
  const status = databaseConnectionError
    ? 503
    : Number.isInteger(error.status)
      ? error.status
      : 500;
  logger.error("Request failed", {
    status,
    method: req.method,
    path: req.path,
    message: error.message,
    userId: req.user?.id,
  });
  const message = databaseConnectionError
    ? "Bad database connection. Check your internet, DNS settings, and Supabase database host, then try again."
    : status >= 500
      ? "The service is temporarily unavailable. Please try again shortly."
      : error.message;
  res.status(status).json({ error: message });
}
module.exports = {
  cookieOptions,
  sessionHours,
  setCsrfCookie,
  requireCsrf,
  authenticate,
  authorize,
  issueSession,
  errorHandler,
};
