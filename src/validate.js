function text(value, label, { min = 1, max = 5000 } = {}) {
  if (typeof value !== "string")
    throw Object.assign(new Error(`${label} is required.`), { status: 400 });
  const clean = value.trim();
  if (
    clean.length < min ||
    clean.length > max ||
    /[\u0000-\u0008\u000B\u000C\u000E-\u001F]/.test(clean)
  )
    throw Object.assign(
      new Error(`${label} must be between ${min} and ${max} characters.`),
      { status: 400 },
    );
  return clean;
}
function email(value) {
  const clean = text(value, "Email", { max: 254 }).toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(clean))
    throw Object.assign(new Error("Enter a valid email address."), {
      status: 400,
    });
  return clean;
}
function password(value) {
  const clean = text(value, "Password", { min: 12, max: 128 });
  if (
    !/[a-z]/.test(clean) ||
    !/[A-Z]/.test(clean) ||
    !/\d/.test(clean) ||
    !/[^A-Za-z0-9]/.test(clean)
  )
    throw Object.assign(
      new Error(
        "Password must include upper- and lower-case letters, a number, and a symbol.",
      ),
      { status: 400 },
    );
  return clean;
}
function positiveInt(value, label = "Value") {
  const num = Number(value);
  if (!Number.isInteger(num) || num <= 0) {
    const error = new Error(`${label} must be a positive integer.`);
    error.status = 400;
    throw error;
  }
  return num;
}

module.exports = { email, password, text, positiveInt };
