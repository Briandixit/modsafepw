const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const {
  findAllMatches,
  findHeuristicAbuse,
  normalizeModerationText,
} = require("../lib/moderation");

const ROOT = path.join(__dirname, "..");
const RULE_FILES = [
  "moderation_rules_10000_final.txt",
  "Moderationstrict_cuss_words_10000.txt",
];

const SAFE_WORDS = new Set([
  "a", "an", "the", "and", "or", "but", "if", "then", "else", "when", "where", "why", "how",
  "i", "you", "he", "she", "it", "we", "they", "me", "him", "her", "us", "them", "my", "your",
  "this", "that", "these", "those", "here", "there", "all", "each", "other", "another",
  "am", "is", "are", "was", "were", "be", "been", "being", "have", "has", "had", "do", "does", "did",
  "can", "could", "will", "would", "shall", "should", "may", "might", "must",
  "not", "never", "to", "for", "of", "in", "on", "at", "by", "with", "from", "as",
  "good", "bad", "great", "nice", "happy", "sad", "love", "like", "ok", "okay", "yes", "no",
  "hello", "hi", "hey", "thanks", "please", "sorry", "friend", "family", "work", "home",
]);

function readRules() {
  const words = [];
  for (const file of RULE_FILES) {
    const fullPath = path.join(ROOT, file);
    const raw = fs.readFileSync(fullPath, "utf8");
    for (const line of raw.split(/\r?\n/)) {
      const normalized = normalizeModerationText(line);
      if (!normalized || SAFE_WORDS.has(normalized)) continue;
      if (!/^[a-z0-9 ]{3,30}$/.test(normalized)) continue;
      words.push(normalized);
    }
  }
  return [...new Set(words)];
}

function hash(value) {
  return crypto.createHash("sha1").update(String(value)).digest("hex").slice(0, 10);
}

function seededShuffle(items, seed = 1337) {
  const list = [...items];
  let state = seed;
  for (let i = list.length - 1; i > 0; i -= 1) {
    state = (state * 1664525 + 1013904223) >>> 0;
    const j = state % (i + 1);
    [list[i], list[j]] = [list[j], list[i]];
  }
  return list;
}

function stretch(word) {
  return word.replace(/[aeiou]/g, "$&$&").replace(/([bcdfghjklmnpqrstvwxyz])$/i, "$1$1");
}

function leet(word) {
  return word
    .replace(/a/g, "@")
    .replace(/e/g, "3")
    .replace(/i/g, "1")
    .replace(/o/g, "0")
    .replace(/s/g, "$")
    .replace(/t/g, "7");
}

function variantsFor(word) {
  const compact = word.replace(/\s+/g, "");
  const chars = compact.split("");
  const variants = [
    ["exact", word],
    ["upper", word.toUpperCase()],
    ["sentence", `you are ${word}`],
    ["punctuated", chars.join(".")],
    ["spaced", chars.join(" ")],
    ["hyphenated", chars.join("-")],
    ["zero_width", chars.join("\u200B")],
    ["leet", leet(compact)],
    ["stretched", stretch(compact)],
    ["wrapped", `stop ${chars.join(".")} now`],
  ];
  return variants;
}

function makeMultiWordCases(seeds) {
  const cases = [];
  for (let i = 0; i < seeds.length - 1; i += 2) {
    const first = seeds[i];
    const second = seeds[i + 1];
    cases.push(["multi_exact", `${first} and ${second}`]);
    cases.push(["multi_obfuscated", `${first.split("").join(".")} and ${second.split("").join(" ")}`]);
  }
  return cases;
}

function detect(text, rules) {
  const matches = findAllMatches(text, rules, { safeWords: SAFE_WORDS, ignoreSafeWords: false });
  const heuristic = findHeuristicAbuse(text);
  return matches.length > 0 || !!heuristic;
}

function main() {
  const rules = readRules();
  const singleTokenRules = rules.filter((word) => !word.includes(" ") && word.length >= 3 && word.length <= 12);
  const phraseRules = rules.filter((word) => word.includes(" ") && word.length <= 30);
  const seeds = seededShuffle(singleTokenRules).slice(0, 400);
  const phraseSeeds = seededShuffle(phraseRules, 9001).slice(0, 100);

  const cases = [];
  for (const seed of seeds) {
    for (const [variant, text] of variantsFor(seed)) {
      cases.push({ kind: variant, text, seedHash: hash(seed) });
    }
  }
  for (const phrase of phraseSeeds) {
    cases.push({ kind: "phrase_exact", text: phrase, seedHash: hash(phrase) });
    cases.push({ kind: "phrase_sentence", text: `you said ${phrase}`, seedHash: hash(phrase) });
  }
  for (const [variant, text] of makeMultiWordCases(seeds.slice(0, 200))) {
    cases.push({ kind: variant, text, seedHash: hash(text) });
  }

  const misses = [];
  const byKind = new Map();
  for (const testCase of cases) {
    const flagged = detect(testCase.text, rules);
    const stats = byKind.get(testCase.kind) || { total: 0, flagged: 0, missed: 0 };
    stats.total += 1;
    if (flagged) stats.flagged += 1;
    else {
      stats.missed += 1;
      misses.push({ kind: testCase.kind, seedHash: testCase.seedHash });
    }
    byKind.set(testCase.kind, stats);
  }

  const flagged = cases.length - misses.length;
  const summary = {
    total: cases.length,
    flagged,
    missed: misses.length,
    flagRate: Number(((flagged / cases.length) * 100).toFixed(2)),
    byKind: Object.fromEntries([...byKind.entries()].sort(([a], [b]) => a.localeCompare(b))),
    sampleMisses: misses.slice(0, 20),
  };

  console.log(JSON.stringify(summary, null, 2));
  if (misses.length) process.exitCode = 1;
}

main();
