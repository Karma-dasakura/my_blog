const crypto = require("crypto");
const key = () => Buffer.from(process.env.DATA_ENCRYPTION_KEY, "hex");

function encrypt(value) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key(), iv);
  const ciphertext = Buffer.concat([
    cipher.update(value, "utf8"),
    cipher.final(),
  ]);
  return `v1:${iv.toString("base64")}.${ciphertext.toString("base64")}.${cipher.getAuthTag().toString("base64")}`;
}
function decrypt(payload) {
  const encoded = payload.startsWith("v1:") ? payload.slice(3) : payload;
  const [iv, ciphertext, tag] = encoded
    .split(".")
    .map((part) => Buffer.from(part, "base64"));
  if (!iv || !ciphertext || !tag)
    throw new Error("Encrypted value has an invalid format.");
  const decipher = crypto.createDecipheriv("aes-256-gcm", key(), iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]).toString("utf8");
}
function emailLookup(email) {
  return crypto
    .createHash("sha256")
    .update(email.trim().toLowerCase())
    .digest("hex");
}
function decryptIfEncrypted(value) {
  return typeof value === "string" && value.startsWith("v1:")
    ? decrypt(value)
    : value;
}
module.exports = { encrypt, decrypt, decryptIfEncrypted, emailLookup };
