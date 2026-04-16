const Database = require('better-sqlite3');
const path = require('path');

const db = new Database(path.join(__dirname, 'moderation.db'));

// Add new columns if they don't exist (ALTER TABLE is idempotent)
try {
  db.exec(`ALTER TABLE users ADD COLUMN abuse_action TEXT DEFAULT 'mask'`);
} catch (e) { /* column already exists */ }
try {
  db.exec(`ALTER TABLE users ADD COLUMN spam_action TEXT DEFAULT 'mask'`);
} catch (e) { /* column already exists */ }

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password TEXT NOT NULL,
    apiKey TEXT UNIQUE NOT NULL,
    plan TEXT DEFAULT 'free',
    customWords TEXT DEFAULT '[]',
    moderationMode TEXT DEFAULT 'moderation',
    abuse_action TEXT DEFAULT 'mask',
    spam_action TEXT DEFAULT 'mask',
    createdAt TEXT
  );

  CREATE TABLE IF NOT EXISTS usage (
    apiKey TEXT PRIMARY KEY,
    count INTEGER DEFAULT 0,
    FOREIGN KEY (apiKey) REFERENCES users(apiKey)
  );

  CREATE TABLE IF NOT EXISTS logs (
    id TEXT PRIMARY KEY,
    apiKey TEXT NOT NULL,
    text TEXT,
    aiCategory TEXT,
    aiConfidence REAL,
    finalCategory TEXT,
    category TEXT,
    flagged INTEGER,
    provider TEXT,
    moderationMode TEXT,
    source TEXT,
    corrected INTEGER DEFAULT 0,
    correctedCategory TEXT,
    matchedWord TEXT,
    flaggedWord TEXT,
    highlightedText TEXT,
    timestamp TEXT,
    FOREIGN KEY (apiKey) REFERENCES users(apiKey)
  );
`);

function getUserByApiKey(apiKey) {
  const stmt = db.prepare('SELECT * FROM users WHERE apiKey = ?');
  const user = stmt.get(apiKey);
  if (user) {
    user.customWords = JSON.parse(user.customWords || '[]');
    user.abuse_action = user.abuse_action || 'mask';
    user.spam_action = user.spam_action || 'mask';
  }
  return user;
}

function createUser(username, passwordHash, apiKey, plan = 'free') {
  const stmt = db.prepare(`
    INSERT INTO users (username, password, apiKey, plan, customWords, moderationMode, abuse_action, spam_action, createdAt)
    VALUES (?, ?, ?, ?, '[]', 'moderation', 'mask', 'mask', ?)
  `);
  stmt.run(username, passwordHash, apiKey, plan, new Date().toISOString());
}

function updateUserPassword(username, passwordHash) {
  const stmt = db.prepare('UPDATE users SET password = ? WHERE username = ?');
  stmt.run(passwordHash, username);
}

function findUserByUsername(username) {
  const stmt = db.prepare('SELECT * FROM users WHERE username = ?');
  const user = stmt.get(username);
  if (user) {
    user.customWords = JSON.parse(user.customWords || '[]');
    user.abuse_action = user.abuse_action || 'mask';
    user.spam_action = user.spam_action || 'mask';
  }
  return user;
}

function updateCustomWords(apiKey, wordsArray) {
  const stmt = db.prepare('UPDATE users SET customWords = ? WHERE apiKey = ?');
  stmt.run(JSON.stringify(wordsArray), apiKey);
}

function updateModerationMode(apiKey, mode) {
  const stmt = db.prepare('UPDATE users SET moderationMode = ? WHERE apiKey = ?');
  stmt.run(mode, apiKey);
}

function updateModerationActions(apiKey, abuse_action, spam_action) {
  const stmt = db.prepare('UPDATE users SET abuse_action = ?, spam_action = ? WHERE apiKey = ?');
  stmt.run(abuse_action, spam_action, apiKey);
}

function getModerationActions(apiKey) {
  const stmt = db.prepare('SELECT abuse_action, spam_action FROM users WHERE apiKey = ?');
  const row = stmt.get(apiKey);
  return {
    abuse_action: row?.abuse_action || 'mask',
    spam_action: row?.spam_action || 'mask'
  };
}

function getUsage(apiKey) {
  const stmt = db.prepare('SELECT count FROM usage WHERE apiKey = ?');
  const row = stmt.get(apiKey);
  return row ? row.count : 0;
}

function incrementUsage(apiKey) {
  const stmt = db.prepare(`
    INSERT INTO usage (apiKey, count) VALUES (?, 1)
    ON CONFLICT(apiKey) DO UPDATE SET count = count + 1
  `);
  stmt.run(apiKey);
}

function addLogEntry(apiKey, entry) {
  const stmt = db.prepare(`
    INSERT INTO logs (
      id, apiKey, text, aiCategory, aiConfidence, finalCategory, category,
      flagged, provider, moderationMode, source, corrected, correctedCategory,
      matchedWord, flaggedWord, highlightedText, timestamp
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  stmt.run(
    entry.id, apiKey, entry.text, entry.aiCategory, entry.aiConfidence,
    entry.finalCategory, entry.category, entry.flagged ? 1 : 0,
    entry.provider, entry.moderationMode, entry.source,
    entry.corrected ? 1 : 0, entry.correctedCategory,
    entry.matchedWord, entry.flaggedWord, entry.highlightedText, entry.timestamp
  );
}

function getLogsForApiKey(apiKey) {
  const stmt = db.prepare('SELECT * FROM logs WHERE apiKey = ? ORDER BY timestamp DESC');
  const rows = stmt.all(apiKey);
  return rows.map(r => ({ ...r, flagged: r.flagged === 1, corrected: r.corrected === 1 }));
}

function getStatsForApiKey(apiKey) {
  const stmt = db.prepare(`
    SELECT 
      COUNT(*) as total,
      SUM(CASE WHEN category = 'abuse' THEN 1 ELSE 0 END) as abuse,
      SUM(CASE WHEN category = 'spam' THEN 1 ELSE 0 END) as spam,
      SUM(CASE WHEN category = 'safe' THEN 1 ELSE 0 END) as safe
    FROM logs WHERE apiKey = ?
  `);
  return stmt.get(apiKey);
}

function updateLogFeedback(id, correctedCategory) {
  const stmt = db.prepare(`
    UPDATE logs SET corrected = 1, correctedCategory = ?, finalCategory = ?, category = ?, flagged = ?
    WHERE id = ?
  `);
  stmt.run(correctedCategory, correctedCategory, correctedCategory, correctedCategory !== 'safe' ? 1 : 0, id);
}

// ----- ADMIN FUNCTIONS -----
function getAllUsers() {
  const stmt = db.prepare(`
    SELECT u.username, u.apiKey, u.plan, u.moderationMode, u.customWords, u.createdAt,
           COALESCE(us.count, 0) as usageCount
    FROM users u
    LEFT JOIN usage us ON u.apiKey = us.apiKey
    ORDER BY u.createdAt DESC
  `);
  const users = stmt.all();
  return users.map(u => ({
    ...u,
    customWordsCount: JSON.parse(u.customWords || '[]').length,
    usage: u.usageCount
  }));
}

function getAllLogsWithUser() {
  const stmt = db.prepare(`
    SELECT l.*, u.username
    FROM logs l
    JOIN users u ON l.apiKey = u.apiKey
    ORDER BY l.timestamp DESC
    LIMIT 1000
  `);
  const rows = stmt.all();
  return rows.map(r => ({ ...r, flagged: r.flagged === 1 }));
}

module.exports = {
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
  getAllLogsWithUser
};