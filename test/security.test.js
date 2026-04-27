const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");

const {
  hashPassword,
  hashApiKey,
  needsPasswordRehash,
  validatePasswordStrength,
  validateProductionEnv,
  verifyStoredPassword,
  isTrustedOriginValue,
} = require("../lib/security");

test("password hashing verifies the original password only", () => {
  const stored = hashPassword("correct horse battery staple", "0123456789abcdef");

  assert.equal(verifyStoredPassword("correct horse battery staple", stored), true);
  assert.equal(verifyStoredPassword("wrong password", stored), false);
  assert.equal(stored.startsWith("pbkdf2$sha256$"), true);
});

test("legacy sha256 passwords still verify for migration", () => {
  const legacy = crypto.createHash("sha256").update("old-password").digest("hex");

  assert.equal(verifyStoredPassword("old-password", legacy), true);
  assert.equal(verifyStoredPassword("not-it", legacy), false);
  assert.equal(needsPasswordRehash(legacy), true);
});

test("password strength requires launch-grade passwords", () => {
  assert.equal(validatePasswordStrength("short").ok, false);
  assert.equal(validatePasswordStrength("LongEnough1!").ok, true);
});

test("api key hashing is deterministic and peppered", () => {
  assert.equal(hashApiKey("secret-key", "pepper"), hashApiKey("secret-key", "pepper"));
  assert.notEqual(hashApiKey("secret-key", "pepper"), hashApiKey("secret-key", "different-pepper"));
});

test("production env validation rejects unsafe placeholders", () => {
  const errors = validateProductionEnv({
    NODE_ENV: "production",
    DATABASE_URL: "postgres://user:pass@example.com:5432/db",
    HF_TOKEN: "hf_token",
    OPENROUTER_API_KEY: "openrouter",
    SESSION_SECRET: "replace-with-long-random-secret",
    ADMIN_PASSWORD_HASH: "replace-with-hash",
    CORS_ORIGIN: "http://example.com",
  });

  assert.equal(errors.length >= 3, true);
});

test("trusted origin guard allows same host and configured origins only", () => {
  assert.equal(isTrustedOriginValue({ origin: "", host: "app.example.com" }), true);
  assert.equal(isTrustedOriginValue({ origin: "https://app.example.com", host: "app.example.com" }), true);
  assert.equal(
    isTrustedOriginValue({
      origin: "https://dashboard.example.com",
      host: "api.example.com",
      allowedOrigins: ["https://dashboard.example.com"],
    }),
    true
  );
  assert.equal(isTrustedOriginValue({ origin: "https://evil.example", host: "app.example.com" }), false);
});
