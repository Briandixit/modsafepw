const crypto = require("crypto");

const PASSWORD_HASH_ITERATIONS = 310000;
const LEGACY_PASSWORD_HASH_ITERATIONS = 120000;
const PASSWORD_HASH_KEYLEN = 32;
const PASSWORD_HASH_DIGEST = "sha256";

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto
    .pbkdf2Sync(String(password), salt, PASSWORD_HASH_ITERATIONS, PASSWORD_HASH_KEYLEN, PASSWORD_HASH_DIGEST)
    .toString("hex");
  return `pbkdf2$${PASSWORD_HASH_DIGEST}$${PASSWORD_HASH_ITERATIONS}$${salt}$${hash}`;
}

function verifyPassword(password, stored) {
  if (!stored) return false;
  let salt;
  let hash;
  let iterations = LEGACY_PASSWORD_HASH_ITERATIONS;
  let digest = PASSWORD_HASH_DIGEST;

  if (stored.startsWith("pbkdf2$")) {
    const parts = stored.split("$");
    if (parts.length !== 5) return false;
    [, digest, iterations, salt, hash] = parts;
    iterations = Number(iterations);
    if (!Number.isInteger(iterations) || iterations < LEGACY_PASSWORD_HASH_ITERATIONS) return false;
  } else if (stored.includes(":")) {
    [salt, hash] = stored.split(":");
  } else {
    return false;
  }

  const test = crypto.pbkdf2Sync(String(password), salt, iterations, PASSWORD_HASH_KEYLEN, digest).toString("hex");
  const storedHash = Buffer.from(hash, "hex");
  const testHash = Buffer.from(test, "hex");
  return storedHash.length === testHash.length && crypto.timingSafeEqual(storedHash, testHash);
}

function verifyStoredPassword(password, stored) {
  if (!stored) return false;
  if (stored.startsWith("pbkdf2$") || stored.includes(":")) return verifyPassword(password, stored);
  const legacyHash = crypto.createHash("sha256").update(password).digest("hex");
  const storedHash = Buffer.from(String(stored));
  const testHash = Buffer.from(legacyHash);
  return storedHash.length === testHash.length && crypto.timingSafeEqual(storedHash, testHash);
}

function needsPasswordRehash(stored) {
  if (!stored || !stored.startsWith("pbkdf2$")) return true;
  const parts = stored.split("$");
  return Number(parts[2]) < PASSWORD_HASH_ITERATIONS;
}

function validatePasswordStrength(password) {
  const value = String(password || "");
  const failures = [];
  if (value.length < 12) failures.push("at least 12 characters");
  if (!/[a-z]/.test(value)) failures.push("one lowercase letter");
  if (!/[A-Z]/.test(value)) failures.push("one uppercase letter");
  if (!/[0-9]/.test(value)) failures.push("one number");
  if (!/[^A-Za-z0-9]/.test(value)) failures.push("one symbol");
  return {
    ok: failures.length === 0,
    message: failures.length ? `Password must include ${failures.join(", ")}.` : "",
  };
}

function createSecretToken(bytes = 32, prefix = "") {
  return `${prefix}${crypto.randomBytes(bytes).toString("base64url")}`;
}

function hashApiKey(apiKey, pepper = "") {
  return crypto.createHmac("sha256", String(pepper || "modsafe-api-key")).update(String(apiKey || "")).digest("hex");
}

function maskSecret(value, visible = 6) {
  const text = String(value || "");
  if (!text) return "";
  if (text.length <= visible * 2) return `${text.slice(0, 2)}...`;
  return `${text.slice(0, visible)}...${text.slice(-visible)}`;
}

function isPlaceholderSecret(value) {
  const text = String(value || "").toLowerCase();
  return !text || text.includes("replace") || text.includes("changeme") || text.includes("your-") || text.includes("secret");
}

function validateProductionEnv(env = process.env) {
  const errors = [];
  const required = ["DATABASE_URL", "HF_TOKEN", "OPENROUTER_API_KEY", "SESSION_SECRET", "ADMIN_PASSWORD_HASH", "CORS_ORIGIN"];
  for (const key of required) {
    if (!env[key]) errors.push(`Missing required environment variable: ${key}`);
  }
  if (String(env.NODE_ENV || "") === "production") {
    if (String(env.SESSION_SECRET || "").length < 48 || isPlaceholderSecret(env.SESSION_SECRET)) {
      errors.push("SESSION_SECRET must be a non-placeholder value at least 48 characters long.");
    }
    if (isPlaceholderSecret(env.ADMIN_PASSWORD_HASH)) {
      errors.push("ADMIN_PASSWORD_HASH must be generated with npm run hash:admin -- <password>.");
    }
    if (!String(env.CORS_ORIGIN || "").startsWith("https://")) {
      errors.push("CORS_ORIGIN must be your exact HTTPS production origin.");
    }
    if (env.API_KEY_PEPPER && (String(env.API_KEY_PEPPER).length < 48 || isPlaceholderSecret(env.API_KEY_PEPPER))) {
      errors.push("API_KEY_PEPPER must be a non-placeholder value at least 48 characters long.");
    }
  }
  return errors;
}

function isTrustedOriginValue({ origin, host, allowedOrigins = [] }) {
  if (!origin) return true;
  if (allowedOrigins.includes(origin)) return true;
  if (!host) return false;
  try {
    return new URL(origin).host === host;
  } catch {
    return false;
  }
}

module.exports = {
  PASSWORD_HASH_ITERATIONS,
  hashPassword,
  verifyPassword,
  verifyStoredPassword,
  needsPasswordRehash,
  validatePasswordStrength,
  createSecretToken,
  hashApiKey,
  maskSecret,
  validateProductionEnv,
  isTrustedOriginValue,
};
