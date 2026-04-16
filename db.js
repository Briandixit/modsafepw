const { Pool } = require("pg");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false,
});

const ready = (async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      username TEXT PRIMARY KEY,
      password TEXT NOT NULL,
      api_key TEXT UNIQUE NOT NULL,
      plan TEXT DEFAULT 'free',
      custom_words TEXT DEFAULT '[]',
      moderation_mode TEXT DEFAULT 'moderation',
      abuse_action TEXT DEFAULT 'mask',
      spam_action TEXT DEFAULT 'mask',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS usage (
      api_key TEXT PRIMARY KEY REFERENCES users(api_key) ON DELETE CASCADE,
      count INTEGER DEFAULT 0
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS logs (
      id TEXT PRIMARY KEY,
      api_key TEXT NOT NULL REFERENCES users(api_key) ON DELETE CASCADE,
      text TEXT,
      ai_category TEXT,
      ai_confidence REAL,
      final_category TEXT,
      category TEXT,
      flagged BOOLEAN DEFAULT FALSE,
      provider TEXT,
      moderation_mode TEXT,
      source TEXT,
      corrected BOOLEAN DEFAULT FALSE,
      corrected_category TEXT,
      matched_word TEXT,
      flagged_word TEXT,
      highlighted_text TEXT,
      timestamp TIMESTAMPTZ DEFAULT NOW()
    );
  `);
})();

function parseJsonArray(value) {
  try {
    if (Array.isArray(value)) return value;
    if (!value) return [];
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function toInt(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function userFromRow(row) {
  if (!row) return null;
  return {
    username: row.username,
    password: row.password,
    apiKey: row.api_key,
    plan: row.plan || "free",
    customWords: parseJsonArray(row.custom_words),
    moderationMode: row.moderation_mode || "moderation",
    abuse_action: row.abuse_action || "mask",
    spam_action: row.spam_action || "mask",
    createdAt: row.created_at,
  };
}

function logFromRow(row) {
  return {
    id: row.id,
    apiKey: row.api_key,
    text: row.text,
    aiCategory: row.ai_category,
    aiConfidence: row.ai_confidence,
    finalCategory: row.final_category,
    category: row.category,
    flagged: row.flagged === true || row.flagged === 1 || row.flagged === "t",
    provider: row.provider,
    moderationMode: row.moderation_mode,
    source: row.source,
    corrected: row.corrected === true || row.corrected === 1 || row.corrected === "t",
    correctedCategory: row.corrected_category,
    matchedWord: row.matched_word,
    flaggedWord: row.flagged_word,
    highlightedText: row.highlighted_text,
    timestamp: row.timestamp,
  };
}

async function ensureReady() {
  return ready;
}

async function getUserByApiKey(apiKey) {
  await ensureReady();
  const res = await pool.query("SELECT * FROM users WHERE api_key = $1", [apiKey]);
  return userFromRow(res.rows[0]);
}

async function createUser(username, passwordHash, apiKey, plan = "free") {
  await ensureReady();
  await pool.query(
    `INSERT INTO users (username, password, api_key, plan, custom_words, moderation_mode, abuse_action, spam_action, created_at)
     VALUES ($1, $2, $3, $4, '[]', 'moderation', 'mask', 'mask', NOW())`,
    [username, passwordHash, apiKey, plan]
  );
}

async function updateUserPassword(username, passwordHash) {
  await ensureReady();
  await pool.query("UPDATE users SET password = $1 WHERE username = $2", [passwordHash, username]);
}

async function findUserByUsername(username) {
  await ensureReady();
  const res = await pool.query("SELECT * FROM users WHERE username = $1", [username]);
  return userFromRow(res.rows[0]);
}

async function updateCustomWords(apiKey, wordsArray) {
  await ensureReady();
  const json = JSON.stringify(Array.isArray(wordsArray) ? wordsArray : []);
  await pool.query("UPDATE users SET custom_words = $1 WHERE api_key = $2", [json, apiKey]);
}

async function updateModerationMode(apiKey, mode) {
  await ensureReady();
  await pool.query("UPDATE users SET moderation_mode = $1 WHERE api_key = $2", [mode, apiKey]);
}

async function updateModerationActions(apiKey, abuse_action, spam_action) {
  await ensureReady();
  await pool.query(
    "UPDATE users SET abuse_action = $1, spam_action = $2 WHERE api_key = $3",
    [abuse_action, spam_action, apiKey]
  );
}

async function getModerationActions(apiKey) {
  await ensureReady();
  const res = await pool.query(
    "SELECT abuse_action, spam_action FROM users WHERE api_key = $1",
    [apiKey]
  );
  const row = res.rows[0];
  return {
    abuse_action: row?.abuse_action || "mask",
    spam_action: row?.spam_action || "mask",
  };
}

async function getUsage(apiKey) {
  await ensureReady();
  const res = await pool.query("SELECT count FROM usage WHERE api_key = $1", [apiKey]);
  return toInt(res.rows[0]?.count, 0);
}

async function incrementUsage(apiKey) {
  await ensureReady();
  await pool.query(
    `INSERT INTO usage (api_key, count)
     VALUES ($1, 1)
     ON CONFLICT (api_key)
     DO UPDATE SET count = usage.count + 1`,
    [apiKey]
  );
}

async function addLogEntry(apiKey, entry) {
  await ensureReady();
  await pool.query(
    `INSERT INTO logs (
      id, api_key, text, ai_category, ai_confidence, final_category, category,
      flagged, provider, moderation_mode, source, corrected, corrected_category,
      matched_word, flagged_word, highlighted_text, timestamp
    ) VALUES (
      $1, $2, $3, $4, $5, $6, $7,
      $8, $9, $10, $11, $12, $13,
      $14, $15, $16, $17
    )`,
    [
      entry.id,
      apiKey,
      entry.text ?? null,
      entry.aiCategory ?? null,
      entry.aiConfidence ?? null,
      entry.finalCategory ?? null,
      entry.category ?? null,
      !!entry.flagged,
      entry.provider ?? null,
      entry.moderationMode ?? null,
      entry.source ?? null,
      !!entry.corrected,
      entry.correctedCategory ?? null,
      entry.matchedWord ?? null,
      entry.flaggedWord ?? null,
      entry.highlightedText ?? null,
      entry.timestamp ?? new Date().toISOString(),
    ]
  );
}

async function getLogsForApiKey(apiKey) {
  await ensureReady();
  const res = await pool.query(
    "SELECT * FROM logs WHERE api_key = $1 ORDER BY timestamp DESC",
    [apiKey]
  );
  return res.rows.map(logFromRow);
}

async function getStatsForApiKey(apiKey) {
  await ensureReady();
  const res = await pool.query(
    `
    SELECT
      COUNT(*)::int AS total,
      COALESCE(SUM(CASE WHEN category = 'abuse' THEN 1 ELSE 0 END), 0)::int AS abuse,
      COALESCE(SUM(CASE WHEN category = 'spam' THEN 1 ELSE 0 END), 0)::int AS spam,
      COALESCE(SUM(CASE WHEN category = 'safe' THEN 1 ELSE 0 END), 0)::int AS safe
    FROM logs
    WHERE api_key = $1
    `,
    [apiKey]
  );
  return res.rows[0] || { total: 0, abuse: 0, spam: 0, safe: 0 };
}

async function updateLogFeedback(id, correctedCategory) {
  await ensureReady();
  await pool.query(
    `
    UPDATE logs
    SET
      corrected = TRUE,
      corrected_category = $1,
      final_category = $1,
      category = $1,
      flagged = CASE WHEN $1 = 'safe' THEN FALSE ELSE TRUE END
    WHERE id = $2
    `,
    [correctedCategory, id]
  );
}

async function getAllUsers() {
  await ensureReady();
  const res = await pool.query(
    `
    SELECT
      u.username,
      u.api_key,
      u.plan,
      u.moderation_mode,
      u.custom_words,
      u.created_at,
      COALESCE(us.count, 0) AS usage_count
    FROM users u
    LEFT JOIN usage us ON u.api_key = us.api_key
    ORDER BY u.created_at DESC
    `
  );

  return res.rows.map((u) => ({
    username: u.username,
    apiKey: u.api_key,
    plan: u.plan,
    moderationMode: u.moderation_mode,
    customWords: parseJsonArray(u.custom_words),
    createdAt: u.created_at,
    customWordsCount: parseJsonArray(u.custom_words).length,
    usage: toInt(u.usage_count, 0),
  }));
}

async function getAllLogsWithUser() {
  await ensureReady();
  const res = await pool.query(
    `
    SELECT l.*, u.username
    FROM logs l
    JOIN users u ON l.api_key = u.api_key
    ORDER BY l.timestamp DESC
    LIMIT 1000
    `
  );

  return res.rows.map((row) => ({
    ...logFromRow(row),
    username: row.username,
  }));
}

module.exports = {
  ready,
  pool,
  getUserByApiKey,
  createUser,
  updateUserPassword,
  findUserByUsername,
  updateCustomWords,
  updateModerationMode,
  updateModerationActions,
  getModerationActions,
  getUsage,
  incrementUsage,
  addLogEntry,
  getLogsForApiKey,
  getStatsForApiKey,
  updateLogFeedback,
  getAllUsers,
  getAllLogsWithUser,
};