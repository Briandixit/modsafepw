const { hashPassword, validatePasswordStrength } = require("../lib/security");

const password = process.argv[2];

if (!password) {
  console.error("Usage: node scripts/hash-admin-password.js <admin-password>");
  process.exit(1);
}

const strength = validatePasswordStrength(password);
if (!strength.ok) {
  console.error(strength.message);
  process.exit(1);
}

console.log(hashPassword(password));
