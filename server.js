require("dotenv").config();

const express = require("express");
const session = require("express-session");
const csrf = require("csurf");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const db = require("./db");

const winston = require("winston");
const SQLiteStore = require("connect-sqlite3")(session);

// --- Logger setup (saves errors to files) ---
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(({ timestamp, level, message }) => `${timestamp} [${level.toUpperCase()}]: ${message}`)
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: "error.log", level: "error" }),
    new winston.transports.File({ filename: "combined.log" })
  ]
});

// Catch crashes and log them
process.on("unhandledRejection", (reason, promise) => {
  logger.error(`Unhandled Rejection at: ${promise}, reason: ${reason}`);
});
process.on("uncaughtException", (err) => {
  logger.error(`Uncaught Exception: ${err.message}`);
  process.exit(1);
});

const { HfInference } = require("@huggingface/inference");

const app = express();
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || "0.0.0.0";

// ---------- Environment validation ----------
const requiredEnv = ["HF_TOKEN", "OPENROUTER_API_KEY", "SESSION_SECRET"];
for (const env of requiredEnv) {
  if (!process.env[env]) {
    console.error(`❌ Missing required environment variable: ${env}`);
    process.exit(1);
  }
}

// ---------- Security middleware ----------
/*app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
    },
  },
}));*/
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: "256kb" }));
app.use(express.urlencoded({ extended: true }));

// ✅ STATIC FILE SERVING (this was missing)
app.use(express.static(path.join(__dirname, "public"), { extensions: ["html"] }));

// Session store (in‑memory for development; use Redis in production)
const sessionStore = new SQLiteStore({ db: "sessions.db", table: "sessions" });
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: sessionStore,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 1000 * 60 * 60 * 24,
  },
}));

// CSRF protection (exclude public endpoints and API key requests)
const csrfProtection = csrf({ cookie: { httpOnly: true, sameSite: "lax" } });
app.use((req, res, next) => {
  // Skip CSRF for requests with an API key
  if (req.headers["x-api-key"]) return next();

  // Exclude public POST endpoints
  const publicEndpoints = ["/login", "/register", "/demo-moderate"];
  if (publicEndpoints.includes(req.path)) return next();

  if (["POST", "PUT", "DELETE", "PATCH"].includes(req.method)) {
    return csrfProtection(req, res, next);
  }
  next();
});

// Rate limiting for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: "Too many login attempts. Try again later." },
  standardHeaders: true,
  legacyHeaders: false,
});

// ---------- Helper functions (same as before) ----------
const timeout = (ms) => new Promise((_, reject) =>
  setTimeout(() => reject(new Error("Request timeout")), ms)
);

const hf = new HfInference(process.env.HF_TOKEN);
const fetchFn = globalThis.fetch
  ? globalThis.fetch.bind(globalThis)
  : (...args) => import("node-fetch").then(({ default: fetch }) => fetch(...args));

const STRICT_RULES_FILE = path.join(__dirname, "moderation_rules_10000_final.txt");
const MODERATE_RULES_FILE = path.join(__dirname, "Moderationstrict_cuss_words_10000.txt");

const PLAN_LIMITS = { free: 1000, starter: 15000, growth: 100000, scale: 500000 };
const RATE_LIMITS_PER_MINUTE = { free: 500, starter: 2000, growth: 10000, scale: 50000 };
const MODERATION_MODES = ["moderation", "off"];

function normalizeUsername(username) {
  return String(username || "").trim().toLowerCase();
}
function normalizeText(text) {
  return String(text || "")
    .normalize("NFKC")
    .toLowerCase()
    .replace(/[\u200B-\u200D\uFEFF]/g, "")
    .replace(/[“”]/g, '"')
    .replace(/[‘’]/g, "'")
    .replace(/[@]/g, "a")
    .replace(/[0]/g, "o")
    .replace(/[1!|]/g, "i")
    .replace(/[3]/g, "e")
    .replace(/[4]/g, "a")
    .replace(/[5]/g, "s")
    .replace(/[7]/g, "t")
    .replace(/[8]/g, "b")
    .replace(/[+]/g, "t")
    .replace(/\s+/g, " ")
    .trim();
}
function normalizeModerationText(text) {
  return normalizeText(text).replace(/[^a-z0-9\s]/g, "").trim();
}
function normalizeCustomWords(value) {
  let raw = [];
  if (Array.isArray(value)) raw = value;
  else if (typeof value === "string") raw = value.split(",");
  else return [];
  return [...new Set(
    raw
      .map((item) => normalizeModerationText(item))
      .filter((w) => w && w.length >= 2 && w.length <= 30)
  )];
}
function normalizeMode(mode) {
  const value = String(mode || "").trim().toLowerCase();
  return MODERATION_MODES.includes(value) ? value : "moderation";
}
function getLimitForPlan(plan) { return PLAN_LIMITS[plan] ?? PLAN_LIMITS.free; }
function getRateLimitForPlan(plan) { return RATE_LIMITS_PER_MINUTE[plan] ?? RATE_LIMITS_PER_MINUTE.free; }
function createApiKey() { return crypto.randomBytes(24).toString("hex"); }
function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.pbkdf2Sync(String(password), salt, 120000, 32, "sha256").toString("hex");
  return `${salt}:${hash}`;
}
function verifyPassword(password, stored) {
  if (!stored || !stored.includes(":")) return stored === String(password);
  const [salt, hash] = stored.split(":");
  const test = crypto.pbkdf2Sync(String(password), salt, 120000, 32, "sha256").toString("hex");
  return crypto.timingSafeEqual(Buffer.from(hash, "hex"), Buffer.from(test, "hex"));
}
function getUserByApiKey(apiKey) { return db.getUserByApiKey(apiKey); }

const KNOWN_SHORT_SLURS = new Set(["bc","mc","chut","lund","gand","gaand","bhos","mad","chod","fuck","shit","ass","dick","cock","piss","cunt","twat","prick","bastard","bitch","slut","whore","crap","damn","hell","suck","fag","nig","retard","idiot","moron"]);
function readWordList(file) {
  try {
    if (!fs.existsSync(file)) return [];
    const raw = fs.readFileSync(file, "utf8");
    const lines = raw.split(/\r?\n/);
    const words = [];
    for (const line of lines) {
      const normalized = normalizeModerationText(line);
      if (!normalized) continue;
      if (normalized.length < 3 && !KNOWN_SHORT_SLURS.has(normalized)) continue;
      if (/^[a-z0-9]$/.test(normalized) && !KNOWN_SHORT_SLURS.has(normalized)) continue;
      words.push(normalized);
    }
    return [...new Set(words)];
  } catch (err) {
    console.error(`Could not read word list from ${file}:`, err.message);
    return [];
  }
}
const STRICT_RULES_CACHE = readWordList(STRICT_RULES_FILE);
const MODERATE_RULES_CACHE = readWordList(MODERATE_RULES_FILE);
const ALL_RULES_CACHE = [...new Set([...STRICT_RULES_CACHE, ...MODERATE_RULES_CACHE])];
console.log(`[ModSafe] Loaded ${ALL_RULES_CACHE.length} moderation rules.`);

const SAFE_WORDS = new Set([
  "a","an","the","and","or","but","if","then","else","when","where","why","how",
  "i","you","he","she","it","we","they","me","him","her","us","them","my","your","his","her","its","our","their",
  "this","that","these","those","here","there","every","some","any","no","none","all","each","every","other","another","both","few","many","much","such",
  "am","is","are","was","were","be","been","being","have","has","had","do","does","did",
  "can","could","will","would","shall","should","may","might","must","need","dare",
  "not","never","ever","always","sometimes","often","rarely","seldom",
  "to","for","of","in","on","at","by","with","from","as","into","onto","upon",
  "about","above","across","after","against","along","among","around","before","behind","below","beneath","beside","between","beyond","during","except","inside","outside","over","past","since","through","throughout","under","until","up","down",
  "good","free money","bada","bad","great","nice","awesome","amazing","wonderful","fantastic","excellent",
  "happy","sad","angry","excited","tired","hungry","thirsty","cold","hot","warm","love","like","hate","enjoy","fun","funny","cool","super","best","better","well",
  "ok","okay","yes","no","hello","hi","hey","thanks","thank","please","sorry","friend","dost","yaar","bhai","behen","family","brother","sister","mother","father",
  "man","woman","person","people","guy","girl","boy","child","kid","adult","india","indian","bharat","hindustan","desi","mumbai","delhi","bangalore",
  "work","job","school","college","university","office","home","house","car","bike","food","water","eat","drink","sleep","rest","play","game","movie","song","music",
  "book","read","write","speak","talk","listen","watch","see","look","hear","day","night","morning","afternoon","evening","today","tomorrow","yesterday",
  "time","year","month","week","hour","minute","second","one","two","three","four","five","six","seven","eight","nine","ten","first","second","third","last","next","previous"
]);

function getRulesForMode(mode) { return normalizeMode(mode) === "moderation" ? ALL_RULES_CACHE : []; }
function escapeRegex(value) { return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }

function findFirstMatch(text, words = [], options = {}) {
  const { ignoreSafeWords = false } = options;
  const normalizedText = normalizeModerationText(text);
  const list = Array.isArray(words) ? words : [];
  
  for (const rawWord of list) {
    const word = normalizeModerationText(rawWord);
    if (!word) continue;
    if (!ignoreSafeWords && SAFE_WORDS.has(word)) continue;
    
    // Single word: use word boundary
    if (!word.includes(" ")) {
      const regex = new RegExp(`\\b${escapeRegex(word)}\\b`, "i");
      if (regex.test(normalizedText)) return word;
    } 
    // Multi-word phrase: simple substring match (case-insensitive)
    else {
      if (normalizedText.includes(word)) return word;
    }
  }
  return null;
}

function findMatchedWord(text, customWords = [], mode = "moderation") {
  const activeMode = normalizeMode(mode);
  const customList = normalizeCustomWords(customWords);
  const ruleList = getRulesForMode(activeMode);
  const customMatch = findFirstMatch(text, customList, { ignoreSafeWords: true });
  if (customMatch) return customMatch;
  return findFirstMatch(text, ruleList, { ignoreSafeWords: false });
}

function buildHighlightedText(text, matchedWord) {
  if (!matchedWord) return null;
  const regex = new RegExp(`(${escapeRegex(matchedWord)})`, "gi");
  return String(text || "").replace(regex, "***$1***");
}

function createSafeResult(provider, moderationMode, matchedWord = null) {
  return { category: "safe", confidence: 0, provider, moderationMode, matchedWord, flaggedWord: null, highlightedText: null };
}

function getAIThreshold(category) { return category === "spam" ? 0.7 : 0.45; }

function getRuleModerationResult(originalText, customWords = [], mode = "moderation") {
  const activeMode = normalizeMode(mode);
  if (!originalText || activeMode === "off") return createSafeResult("safe", activeMode);
  const customList = normalizeCustomWords(customWords);
  const customMatch = findFirstMatch(originalText, customList, { ignoreSafeWords: true });
  if (customMatch) {
    return { category: "abuse", confidence: 1, provider: "rules", moderationMode: activeMode, matchedWord: customMatch, flaggedWord: customMatch, highlightedText: buildHighlightedText(originalText, customMatch) };
  }
  const ruleMatch = findFirstMatch(originalText, ALL_RULES_CACHE, { ignoreSafeWords: false });
  if (ruleMatch) {
    return { category: "abuse", confidence: 1, provider: "rules", moderationMode: activeMode, matchedWord: ruleMatch, flaggedWord: ruleMatch, highlightedText: buildHighlightedText(originalText, ruleMatch) };
  }
  return null;
}

async function moderateWithOpenRouter(text) {
  const apiKey = process.env.OPENROUTER_API_KEY;
  if (!apiKey) return null;
  try {
    const model = process.env.OPENROUTER_MODEL || "openai/gpt-4o-mini";
    const systemPrompt = `You are a content moderation classifier for English, Hindi, Hinglish, slang, and regional language. Classify the text into exactly one category: "abuse", "spam", or "safe". Use a conservative moderation standard. Return ONLY valid JSON in this exact format: {"category":"safe","confidence":0}. Confidence must be a number from 0 to 1. No markdown, no explanation, no extra keys.`;
    const response = await Promise.race([
      fetchFn("https://openrouter.ai/api/v1/chat/completions", {
        method: "POST",
        headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
        body: JSON.stringify({ model, temperature: 0, max_tokens: 90, messages: [{ role: "system", content: systemPrompt }, { role: "user", content: text }] }),
      }),
      timeout(3000),
    ]);
    if (!response || !response.ok) return null;
    const data = await response.json();
    const content = data?.choices?.[0]?.message?.content;
    if (!content) return null;
    const cleaned = content.trim().replace(/^```json\s*/i, "").replace(/^```\s*/i, "").replace(/\s*```$/i, "").trim();
    let parsed;
    try { parsed = JSON.parse(cleaned); } catch { const match = cleaned.match(/\{[\s\S]*\}/); if (!match) return null; parsed = JSON.parse(match[0]); }
    const category = String(parsed.category || "safe").toLowerCase();
    const confidence = Number(parsed.confidence || 0);
    if (!["safe","spam","abuse"].includes(category) || isNaN(confidence)) return null;
    return { category, confidence: Math.min(Math.max(confidence, 0), 1) };
  } catch (err) {
    console.error("OpenRouter error:", err.message);
    return null;
  }
}

async function classifyModeration(originalText, customWords = [], mode = "moderation") {
  const activeMode = normalizeMode(mode);
  if (!originalText || activeMode === "off") return createSafeResult("safe", activeMode);
  const ruleResult = getRuleModerationResult(originalText, customWords, activeMode);
  if (ruleResult) return ruleResult;
  const aiResult = await moderateWithOpenRouter(originalText);
  if (aiResult && aiResult.category !== "safe" && aiResult.confidence >= getAIThreshold(aiResult.category)) {
    const matchedWord = findMatchedWord(originalText, customWords, activeMode);
    return { category: aiResult.category, confidence: Number(aiResult.confidence.toFixed(4)), provider: "openrouter", moderationMode: activeMode, matchedWord, flaggedWord: matchedWord, highlightedText: matchedWord ? buildHighlightedText(originalText, matchedWord) : null };
  }
  return createSafeResult("safe", activeMode);
}

function applyAction(text, flaggedWords, action, category) {
  if (action === "block") return { blocked: true };
  if (!text) return { processedText: text, blocked: false };
  let processed = normalizeModerationText(text);
  if (flaggedWords.length > 0) {
    for (const word of flaggedWords) {
      const regex = new RegExp(`\\b${escapeRegex(word)}\\b`, "gi");
      switch (action) {
        case "mask": processed = processed.replace(regex, "***"); break;
        case "remove": processed = processed.replace(regex, ""); break;
        case "replace": processed = processed.replace(regex, "[removed]"); break;
        default: processed = processed.replace(regex, "***");
      }
    }
    if (action === "remove") processed = processed.replace(/\s+/g, " ").trim();
    return { processedText: processed, blocked: false };
  }
  switch (action) {
    case "mask": return { processedText: "***", blocked: false };
    case "remove": return { processedText: "", blocked: false };
    case "replace": return { processedText: "[removed]", blocked: false };
    default: return { processedText, blocked: false };
  }
}

function pushModerationEntry(apiKey, text, result, source, moderationMode = "moderation", extra = {}) {
  const entry = {
    id: crypto.randomUUID(),
    text,
    aiCategory: result.category,
    aiConfidence: Number(Number(result.confidence || 0).toFixed(2)),
    finalCategory: result.category,
    category: result.category,
    flagged: result.category !== "safe",
    provider: result.provider || "openrouter",
    moderationMode: normalizeMode(moderationMode),
    source,
    corrected: false,
    correctedCategory: null,
    matchedWord: extra.matchedWord || result.matchedWord || null,
    flaggedWord: extra.flaggedWord || extra.matchedWord || result.matchedWord || null,
    highlightedText: extra.highlightedText || result.highlightedText || null,
    timestamp: new Date().toISOString(),
  };
  db.addLogEntry(apiKey, entry);
  return entry;
}

// Rate limiting (in-memory)
const rateLimits = new Map();
function isRateLimited(apiKey, plan) {
  const limit = getRateLimitForPlan(plan);
  const now = Date.now();
  const entry = rateLimits.get(apiKey);
  if (!entry || now - entry.windowStart >= 60000) {
    rateLimits.set(apiKey, { count: 1, windowStart: now });
    return false;
  }
  entry.count += 1;
  return entry.count > limit;
}
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of rateLimits.entries()) {
    if (now - entry.windowStart > 300000) rateLimits.delete(key);
  }
}, 300000);

// ---------- Authentication middleware ----------
async function authenticate(req, res, next) {
  if (req.session && req.session.userId) {
    const user = db.findUserByUsername(req.session.userId);
    if (user) {
      req.user = user;
      return next();
    }
  }
  const apiKey = req.headers["x-api-key"];
  if (apiKey) {
    const user = getUserByApiKey(apiKey);
    if (user) {
      req.user = user;
      return next();
    }
  }
  res.status(401).json({ error: "Unauthorized" });
}

// ---------- Routes ----------
app.get("/", (req, res) => {
  const candidates = ["landingpage.html", "landpage.html", "index.html"];
  for (const fileName of candidates) {
    const fullPath = path.join(__dirname, fileName);
    if (fs.existsSync(fullPath)) return res.sendFile(fullPath);
  }
  res.status(404).send("ModSafe API");
});

app.get("/health", (req, res) => {
  res.json({ ok: true, service: "ModSafe", version: "1.0.0", plans: PLAN_LIMITS, rateLimits: RATE_LIMITS_PER_MINUTE, modes: MODERATION_MODES, rulesCount: ALL_RULES_CACHE.length });
});

app.post("/register", async (req, res) => {
  const username = normalizeUsername(req.body.username);
  const password = String(req.body.password || "");
  if (!username || !password) return res.status(400).json({ error: "Missing username or password" });
  if (username.length < 3) return res.status(400).json({ error: "Username must be at least 3 characters" });
  if (password.length < 8) return res.status(400).json({ error: "Password must be at least 8 characters" });
  const existing = db.findUserByUsername(username);
  if (existing) return res.status(409).json({ error: "User already exists" });
  const apiKey = createApiKey();
  const passwordHash = hashPassword(password);
  db.createUser(username, passwordHash, apiKey, "free");
  req.session.userId = username;
  req.session.apiKey = apiKey;
  res.status(201).json({
    apiKey,
    username,
    plan: "free",
    customWords: [],
    moderationMode: "moderation",
    abuse_action: "mask",
    spam_action: "mask",
  });
});

app.post("/login", authLimiter, async (req, res) => {
  const username = normalizeUsername(req.body.username);
  const password = String(req.body.password || "");
  if (!username || !password) return res.status(400).json({ error: "Missing username or password" });
  const user = db.findUserByUsername(username);
  if (!user || !verifyPassword(password, user.password)) {
    return res.status(401).json({ error: "Invalid login" });
  }
  if (!String(user.password).includes(":")) {
    const newHash = hashPassword(password);
    db.updateUserPassword(username, newHash);
  }
  req.session.userId = user.username;
  req.session.apiKey = user.apiKey;
  res.json({
    apiKey: user.apiKey,
    username: user.username,
    plan: user.plan || "free",
    customWords: normalizeCustomWords(user.customWords || []),
    moderationMode: normalizeMode(user.moderationMode || "moderation"),
    abuse_action: user.abuse_action || "mask",
    spam_action: user.spam_action || "mask",
  });
});

app.post("/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get("/me", authenticate, (req, res) => {
  const actions = db.getModerationActions(req.user.apiKey);
  res.json({
    username: req.user.username,
    apiKey: req.user.apiKey,
    plan: req.user.plan || "free",
    customWords: normalizeCustomWords(req.user.customWords || []),
    moderationMode: normalizeMode(req.user.moderationMode || "moderation"),
    abuse_action: actions.abuse_action,
    spam_action: actions.spam_action,
  });
});

app.get("/usage", authenticate, (req, res) => {
  const apiKey = req.user.apiKey;
  const plan = req.user.plan || "free";
  const limit = getLimitForPlan(plan);
  const used = db.getUsage(apiKey);
  res.json({ used, limit, remaining: Math.max(0, limit - used), plan });
});

app.get("/stats", authenticate, (req, res) => {
  const stats = db.getStatsForApiKey(req.user.apiKey) || { total: 0, abuse: 0, spam: 0, safe: 0 };
  res.json(stats);
});

app.get("/data", authenticate, (req, res) => {
  const logs = db.getLogsForApiKey(req.user.apiKey);
  res.json(logs);
});

app.get("/custom-words", authenticate, (req, res) => {
  const user = db.getUserByApiKey(req.user.apiKey);
  res.json({ customWords: user ? user.customWords : [] });
});

app.post("/custom-words", authenticate, (req, res) => {
  const words = normalizeCustomWords(req.body.customWords ?? req.body.words ?? []);
  db.updateCustomWords(req.user.apiKey, words);
  res.json({ ok: true, customWords: words });
});

app.delete("/custom-words", authenticate, (req, res) => {
  db.updateCustomWords(req.user.apiKey, []);
  res.json({ ok: true, customWords: [] });
});

app.get("/moderation-mode", authenticate, (req, res) => {
  res.json({ moderationMode: normalizeMode(req.user.moderationMode || "moderation") });
});

app.post("/moderation-mode", authenticate, (req, res) => {
  const nextMode = normalizeMode(req.body.mode);
  db.updateModerationMode(req.user.apiKey, nextMode);
  res.json({ ok: true, moderationMode: nextMode });
});

app.get("/moderation-actions", authenticate, (req, res) => {
  const actions = db.getModerationActions(req.user.apiKey);
  res.json(actions);
});

app.post("/moderation-actions", authenticate, (req, res) => {
  const abuse = String(req.body.abuse_action || "mask").toLowerCase();
  const spam = String(req.body.spam_action || "mask").toLowerCase();
  const valid = ["mask","remove","replace","block"];
  if (!valid.includes(abuse) || !valid.includes(spam)) {
    return res.status(400).json({ error: "Invalid action. Use mask, remove, replace, or block." });
  }
  db.updateModerationActions(req.user.apiKey, abuse, spam);
  res.json({ ok: true, abuse_action: abuse, spam_action: spam });
});

app.post("/feedback", authenticate, (req, res) => {
  const id = String(req.body.id || "").trim();
  const correctedCategory = String(req.body.correctedCategory || "").trim().toLowerCase();
  if (!id) return res.status(400).json({ error: "Missing log id" });
  if (!["safe","spam","abuse"].includes(correctedCategory)) return res.status(400).json({ error: "Invalid corrected category" });
  db.updateLogFeedback(id, correctedCategory);
  res.json({ ok: true, id, correctedCategory });
});

app.post("/moderate", authenticate, async (req, res) => {
  if (req.body.text && req.body.text.length > 5000) return res.status(400).json({ error: "Text too long" });
  const apiKey = req.user.apiKey;
  const plan = req.user.plan || "free";
  const limit = getLimitForPlan(plan);
  const text = String(req.body.text || "").trim();
  const customWords = normalizeCustomWords(req.user.customWords || []);
  const mode = normalizeMode(req.body.mode || req.user.moderationMode || "moderation");
  const actions = db.getModerationActions(apiKey);
  if (isRateLimited(apiKey, plan)) return res.status(429).json({ error: "Rate limit exceeded", limitPerMinute: getRateLimitForPlan(plan) });
  if (!text) return res.json({ flagged: false, category: "safe", confidence: 0, provider: "safe", moderationMode: mode, matchedWord: null, flaggedWord: null, highlightedText: null, processedText: "" });
  if (mode === "off") {
    const entry = pushModerationEntry(apiKey, text, { category: "safe", confidence: 0, provider: "off" }, "live", mode);
    return res.json({ id: entry.id, flagged: false, category: "safe", confidence: 0, provider: "off", moderationMode: mode, matchedWord: null, flaggedWord: null, highlightedText: null, processedText: text });
  }
  const currentUsage = db.getUsage(apiKey);
  if (currentUsage >= limit) return res.status(429).json({ error: "Plan limit reached", limit, used: currentUsage, remaining: 0 });
  const result = await classifyModeration(text, customWords, mode);
  let action = "mask";
  if (result.category === "abuse") action = actions.abuse_action;
  else if (result.category === "spam") action = actions.spam_action;
  const flaggedWords = result.matchedWord ? [result.matchedWord] : [];
  const { processedText, blocked } = applyAction(text, flaggedWords, action, result.category);
  if (blocked) return res.status(403).json({ error: `Content blocked due to ${result.category}`, category: result.category, confidence: result.confidence, moderationMode: mode });
  const entry = pushModerationEntry(apiKey, text, result, "live", mode, { matchedWord: result.matchedWord, flaggedWord: result.matchedWord, highlightedText: result.highlightedText });
  db.incrementUsage(apiKey);
  res.json({ id: entry.id, flagged: result.category !== "safe", category: result.category, confidence: result.confidence, provider: result.provider, moderationMode: mode, matchedWord: result.matchedWord, flaggedWord: result.matchedWord, highlightedText: result.highlightedText, processedText });
});

app.post("/test-moderate", authenticate, async (req, res) => {
  if (req.body.text && req.body.text.length > 5000) return res.status(400).json({ error: "Text too long" });
  const text = String(req.body.text || "").trim();
  const customWords = normalizeCustomWords(req.user.customWords || []);
  const mode = normalizeMode(req.body.mode || req.user.moderationMode || "moderation");
  const actions = db.getModerationActions(req.user.apiKey);
  let actionOverride = req.body.action_override;
  if (actionOverride && !["mask","remove","replace","block"].includes(actionOverride)) actionOverride = null;
  if (!text) return res.json({ flagged: false, category: "safe", confidence: 0, provider: "safe", moderationMode: mode, matchedWord: null, flaggedWord: null, highlightedText: null, processedText: "" });
  const result = await classifyModeration(text, customWords, mode);
  let action = "mask";
  if (result.category === "abuse") action = actionOverride || actions.abuse_action;
  else if (result.category === "spam") action = actionOverride || actions.spam_action;
  const flaggedWords = result.matchedWord ? [result.matchedWord] : [];
  const { processedText, blocked } = applyAction(text, flaggedWords, action, result.category);
  if (blocked) return res.json({ flagged: true, category: result.category, confidence: result.confidence, provider: result.provider, moderationMode: mode, matchedWord: result.matchedWord, flaggedWord: result.matchedWord, highlightedText: result.highlightedText, blocked: true, errorMessage: `Would be blocked (${result.category})` });
  const entry = pushModerationEntry(req.user.apiKey, text, result, "test", mode, { matchedWord: result.matchedWord, flaggedWord: result.matchedWord, highlightedText: result.highlightedText });
  res.json({ id: entry.id, flagged: result.category !== "safe", category: result.category, confidence: result.confidence, provider: result.provider, moderationMode: mode, matchedWord: result.matchedWord, flaggedWord: result.matchedWord, highlightedText: result.highlightedText, processedText });
});

app.post("/demo-moderate", (req, res) => {
  const text = String(req.body.text || "").trim();
  const mode = normalizeMode(req.body.mode || "moderation");
  if (!text) return res.json({ flagged: false, category: "safe", confidence: 0, provider: "rules", moderationMode: mode, matchedWord: null, flaggedWord: null, highlightedText: null });
  const result = (() => {
    const activeMode = normalizeMode(mode);
    if (!text || activeMode === "off") return createSafeResult("safe", activeMode);
    const ruleResult = getRuleModerationResult(text, [], activeMode);
    if (ruleResult) return ruleResult;
    return createSafeResult("rules", activeMode);
  })();
  res.json({ flagged: result.category !== "safe", category: result.category, confidence: result.confidence, provider: result.provider || "rules", moderationMode: result.moderationMode || mode, matchedWord: result.matchedWord, flaggedWord: result.flaggedWord || result.matchedWord, highlightedText: result.highlightedText });
});

app.post("/moderate-batch", authenticate, async (req, res) => {
  const texts = req.body.texts;
  if (!Array.isArray(texts) || texts.length === 0) return res.status(400).json({ error: "Missing or empty 'texts' array" });
  if (texts.length > 100) return res.status(400).json({ error: "Batch size cannot exceed 100" });
  for (const t of texts) if (typeof t !== "string" || t.length > 5000) return res.status(400).json({ error: "Each text must be a string ≤5000 chars" });
  const apiKey = req.user.apiKey;
  const plan = req.user.plan || "free";
  const limit = getLimitForPlan(plan);
  const customWords = normalizeCustomWords(req.user.customWords || []);
  const mode = normalizeMode(req.body.mode || req.user.moderationMode || "moderation");
  const actions = db.getModerationActions(apiKey);
  if (isRateLimited(apiKey, plan)) return res.status(429).json({ error: "Rate limit exceeded", limitPerMinute: getRateLimitForPlan(plan) });
  let currentUsage = db.getUsage(apiKey);
  const needed = texts.length;
  if (currentUsage + needed > limit) return res.status(429).json({ error: "Plan limit would be exceeded", limit, used: currentUsage, remaining: limit - currentUsage });
  const results = [];
  for (const text of texts) {
    const result = await classifyModeration(text, customWords, mode);
    let action = "mask";
    if (result.category === "abuse") action = actions.abuse_action;
    else if (result.category === "spam") action = actions.spam_action;
    const flaggedWords = result.matchedWord ? [result.matchedWord] : [];
    const { processedText, blocked } = applyAction(text, flaggedWords, action, result.category);
    const entry = pushModerationEntry(apiKey, text, result, "batch", mode, { matchedWord: result.matchedWord, flaggedWord: result.matchedWord, highlightedText: result.highlightedText });
    results.push({ id: entry.id, originalText: text, flagged: result.category !== "safe", category: result.category, confidence: result.confidence, provider: result.provider, moderationMode: mode, matchedWord: result.matchedWord, flaggedWord: result.matchedWord, highlightedText: result.highlightedText, processedText, blocked });
  }
  for (let i = 0; i < needed; i++) db.incrementUsage(apiKey);
  res.json({ success: true, count: needed, results });
});

// ---------- Admin endpoints (keep sessions, also accept Bearer token) ----------
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH;

function verifyAdmin(username, password) {
  if (!ADMIN_PASSWORD_HASH) {
    logger.error("ADMIN_PASSWORD_HASH not set in .env");
    return false;
  }
  const hash = crypto.createHash("sha256").update(password).digest("hex");
  return username === ADMIN_USERNAME && hash === ADMIN_PASSWORD_HASH;
}

// Middleware to accept either session or Bearer token
app.use("/admin", (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith("Bearer ")) {
    const token = authHeader.slice(7);
    if (req.session.adminToken === token) {
      return next();
    }
  }
  next();
});

app.post("/admin/login", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password || !verifyAdmin(username, password)) {
    return res.status(401).json({ error: "Invalid admin credentials" });
  }
  const token = crypto.randomBytes(32).toString("hex");
  req.session.adminToken = token;
  req.session.adminUser = username;
  res.json({ token });
});

app.get("/admin/users", (req, res) => {
  if (!req.session.adminToken) return res.status(401).json({ error: "Unauthorized" });
  const users = db.getAllUsers();
  res.json({ users });
});

app.get("/admin/logs", (req, res) => {
  if (!req.session.adminToken) return res.status(401).json({ error: "Unauthorized" });
  const logs = db.getAllLogsWithUser();
  res.json({ logs });
});

app.use((err, req, res, next) => {
  if (err.code === "EBADCSRFTOKEN") return res.status(403).json({ error: "Invalid CSRF token" });
  console.error(err);
  res.status(500).json({ error: "Internal server error" });
});

app.listen(PORT, HOST, () => {
  console.log(`🚀 ModSafe server running on http://${HOST}:${PORT}`);
});