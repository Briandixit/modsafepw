const ZERO_WIDTH_RE = /[\u200B-\u200D\uFEFF]/g;

function normalizeText(text) {
  return String(text || "")
    .normalize("NFKC")
    .toLowerCase()
    .replace(ZERO_WIDTH_RE, "")
    .replace(/[“”]/g, '"')
    .replace(/[‘’]/g, "'")
    .replace(/(?<=[a-z])!(?=[a-z])/g, "i")
    .replace(/[@]/g, "a")
    .replace(/[0]/g, "o")
    .replace(/[1|]/g, "i")
    .replace(/[3]/g, "e")
    .replace(/[4]/g, "a")
    .replace(/[5$]/g, "s")
    .replace(/[7]/g, "t")
    .replace(/[8]/g, "b")
    .replace(/[+]/g, "t")
    .replace(/\s+/g, " ")
    .trim();
}

function normalizeModerationText(text) {
  return normalizeText(text).replace(/[^a-z0-9\s]/g, "").replace(/\s+/g, " ").trim();
}

function normalizeCompactText(text) {
  return normalizeText(text).replace(/[^a-z0-9]/g, "");
}

function squeezeRepeatedLetters(value) {
  return String(value || "").replace(/([a-z])\1{1,}/g, "$1");
}

function normalizeWord(value) {
  return normalizeModerationText(value);
}

function normalizeCustomWords(value) {
  let raw = [];
  if (Array.isArray(value)) raw = value;
  else if (typeof value === "string") raw = value.split(",");
  else return [];
  return [...new Set(
    raw
      .map((item) => normalizeWord(item))
      .filter((word) => word && word.length >= 2 && word.length <= 30)
  )];
}

function escapeRegex(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function buildSingleLetterRuns(tokens) {
  const runs = [];
  let current = "";

  for (const token of tokens) {
    if (/^[a-z0-9]$/.test(token)) {
      current += token;
      continue;
    }
    if (current.length >= 3) runs.push(current);
    current = "";
  }

  if (current.length >= 3) runs.push(current);
  return runs;
}

function makeSearchVariants(text) {
  const normalized = normalizeModerationText(text);
  const tokens = normalized ? normalized.split(/\s+/).filter(Boolean) : [];
  const compact = normalizeCompactText(text);
  const squeezedTokens = tokens.map(squeezeRepeatedLetters);
  const squeezedText = squeezedTokens.join(" ");
  const squeezedCompact = squeezeRepeatedLetters(compact);
  const singleLetterRuns = buildSingleLetterRuns(tokens);

  return {
    normalized,
    tokens,
    compact,
    squeezedText,
    squeezedTokens,
    squeezedCompact,
    singleLetterRuns,
  };
}

function isSafeWord(word, safeWords, ignoreSafeWords) {
  return !ignoreSafeWords && safeWords?.has(word);
}

function findTokenMatch(word, variants) {
  const regex = new RegExp(`\\b${escapeRegex(word)}\\b`, "i");
  if (regex.test(variants.normalized)) return true;
  if (word.length >= 3) {
    const squeezedWord = squeezeRepeatedLetters(word);
    const squeezedRegex = new RegExp(`\\b${escapeRegex(squeezedWord)}\\b`, "i");
    if (squeezedRegex.test(variants.squeezedText)) return true;
  }
  return false;
}

function findCompactMatch(word, variants, options = {}) {
  const minLength = 3;
  if (word.length < minLength) return false;
  const compactWord = normalizeCompactText(word);
  if (compactWord.length < minLength) return false;
  const strictShortMatch = compactWord.length < 4 && !options.allowShortCompact;

  if (strictShortMatch) {
    const squeezedWord = squeezeRepeatedLetters(compactWord);
    return variants.singleLetterRuns.some((run) => (
      run === compactWord || squeezeRepeatedLetters(run) === squeezedWord
    ));
  }

  if (variants.singleLetterRuns.some((run) => run.includes(compactWord))) return true;

  const squeezedWord = squeezeRepeatedLetters(compactWord);
  if (squeezedWord.length >= minLength && variants.singleLetterRuns.map(squeezeRepeatedLetters).some((run) => run.includes(squeezedWord))) {
    return true;
  }

  const compactPattern = new RegExp(`(?:^|[^a-z0-9])${escapeRegex(compactWord)}(?:$|[^a-z0-9])`, "i");
  if (compactPattern.test(` ${variants.compact} `)) return true;

  if (squeezedWord.length >= minLength) {
    const squeezedPattern = new RegExp(`(?:^|[^a-z0-9])${escapeRegex(squeezedWord)}(?:$|[^a-z0-9])`, "i");
    return squeezedPattern.test(` ${variants.squeezedCompact} `);
  }

  return false;
}

function findPhraseMatch(word, variants) {
  if (variants.normalized.includes(word)) return true;
  if (word.length >= 4 && variants.squeezedText.includes(squeezeRepeatedLetters(word))) return true;
  return false;
}

const DIRECT_ATTACK_TERMS = [
  "idiot",
  "moron",
  "stupid",
  "loser",
  "trash",
  "worthless",
  "pathetic",
  "disgusting",
];

const TARGET_TERMS = [
  "you",
  "u",
  "ur",
  "youre",
  "tum",
  "tu",
  "tera",
  "teri",
  "tujhe",
  "aap",
];

const THREAT_PHRASES = [
  "kill yourself",
  "go die",
  "die now",
  "i will kill you",
  "ill kill you",
];

function findHeuristicAbuse(text) {
  const variants = makeSearchVariants(text);
  const normalized = variants.normalized;
  if (!normalized) return null;

  for (const phrase of THREAT_PHRASES) {
    if (findPhraseMatch(phrase, variants)) return phrase;
  }

  const targetPattern = TARGET_TERMS.map(escapeRegex).join("|");
  for (const term of DIRECT_ATTACK_TERMS) {
    const termPattern = escapeRegex(term);
    const targetedBefore = new RegExp(`\\b(?:${targetPattern})\\b(?:\\s+\\w+){0,4}\\s+\\b${termPattern}\\b`, "i");
    const targetedAfter = new RegExp(`\\b${termPattern}\\b(?:\\s+\\w+){0,3}\\s+\\b(?:${targetPattern})\\b`, "i");
    if (targetedBefore.test(normalized) || targetedAfter.test(normalized)) return term;
  }

  return null;
}

function findFirstMatch(text, words = [], options = {}) {
  const { ignoreSafeWords = false, safeWords = new Set() } = options;
  const variants = makeSearchVariants(text);
  const list = Array.isArray(words) ? words : [];

  for (const rawWord of list) {
    const word = normalizeWord(rawWord);
    if (!word) continue;
    if (isSafeWord(word, safeWords, ignoreSafeWords)) continue;

    if (word.includes(" ")) {
      if (findPhraseMatch(word, variants)) return word;
      continue;
    }

    if (findTokenMatch(word, variants) || findCompactMatch(word, variants, { allowShortCompact: ignoreSafeWords })) return word;
  }

  return null;
}

function findAllMatches(text, words = [], options = {}) {
  const { ignoreSafeWords = false, safeWords = new Set() } = options;
  const variants = makeSearchVariants(text);
  const list = Array.isArray(words) ? words : [];
  const matches = [];
  const seen = new Set();

  for (const rawWord of list) {
    const word = normalizeWord(rawWord);
    if (!word || seen.has(word)) continue;
    if (isSafeWord(word, safeWords, ignoreSafeWords)) continue;

    const matched = word.includes(" ")
      ? findPhraseMatch(word, variants)
      : findTokenMatch(word, variants) || findCompactMatch(word, variants, { allowShortCompact: ignoreSafeWords });
    if (matched) {
      matches.push(word);
      seen.add(word);
    }
  }

  return matches;
}

function buildHighlightPattern(matchedWord) {
  const normalizedMatch = normalizeWord(matchedWord);
  if (!normalizedMatch) return null;
  if (normalizedMatch.includes(" ")) return new RegExp(`(${escapeRegex(matchedWord)})`, "gi");
  const loosePattern = normalizedMatch
    .split("")
    .map((char) => `${escapeRegex(char)}+`)
    .join("[^a-zA-Z0-9]*");
  return new RegExp(`(${loosePattern})`, "gi");
}

function buildHighlightedText(text, matchedWords) {
  const matches = Array.isArray(matchedWords) ? matchedWords : [matchedWords];
  if (!matches.length || !matches[0]) return null;
  const original = String(text || "");
  let highlighted = original;

  for (const matchedWord of matches.filter(Boolean).sort((a, b) => String(b).length - String(a).length)) {
    const exactRegex = new RegExp(`(${escapeRegex(matchedWord)})`, "gi");
    if (exactRegex.test(highlighted)) {
      highlighted = highlighted.replace(exactRegex, "***$1***");
      continue;
    }

    const looseRegex = buildHighlightPattern(matchedWord);
    if (looseRegex) highlighted = highlighted.replace(looseRegex, "***$1***");
  }

  return highlighted;
}

function buildActionRegex(word) {
  const normalized = normalizeWord(word);
  if (!normalized) return null;
  if (normalized.includes(" ")) {
    const phrasePattern = normalized.split(/\s+/).map(escapeRegex).join("\\s+");
    return new RegExp(`\\b${phrasePattern}\\b`, "gi");
  }
  const flexibleWord = normalized
    .split("")
    .map((char) => `${escapeRegex(char)}+`)
    .join("\\s*");
  return new RegExp(`\\b${flexibleWord}\\b`, "gi");
}

module.exports = {
  normalizeText,
  normalizeModerationText,
  normalizeCompactText,
  squeezeRepeatedLetters,
  normalizeCustomWords,
  escapeRegex,
  makeSearchVariants,
  findFirstMatch,
  findAllMatches,
  findHeuristicAbuse,
  buildHighlightedText,
  buildActionRegex,
};
