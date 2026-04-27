const test = require("node:test");
const assert = require("node:assert/strict");

const {
  buildHighlightedText,
  buildActionRegex,
  findHeuristicAbuse,
  findAllMatches,
  findFirstMatch,
  normalizeModerationText,
} = require("../lib/moderation");

test("normalization handles common leetspeak and punctuation", () => {
  assert.equal(normalizeModerationText("f00 b@r!!!"), "foo bar");
});

test("manual matcher catches punctuation-separated custom words", () => {
  assert.equal(findFirstMatch("you f.o.o.b.a.r", ["foobar"], { ignoreSafeWords: true }), "foobar");
});

test("manual matcher catches spaced-letter custom words", () => {
  assert.equal(findFirstMatch("you are f o o b a r", ["foobar"], { ignoreSafeWords: true }), "foobar");
});

test("manual matcher catches spaced short rule words conservatively", () => {
  assert.equal(findFirstMatch("you are a b c", ["abc"]), "abc");
  assert.equal(findFirstMatch("x a b c y", ["abc"]), null);
});

test("manual matcher catches stretched custom words", () => {
  assert.equal(findFirstMatch("you are foooobaaaar", ["foobar"], { ignoreSafeWords: true }), "foobar");
});

test("manual matcher catches stretched short rule words", () => {
  assert.equal(findFirstMatch("you are fooo", ["foo"]), "foo");
});

test("manual matcher avoids short-word matches inside normal words", () => {
  assert.equal(findFirstMatch("that was classy", ["ass"], { ignoreSafeWords: true }), null);
});

test("manual matcher returns every matched custom word", () => {
  assert.deepEqual(
    findAllMatches("foo and b a r are both bad", ["foo", "bar"], { ignoreSafeWords: true }),
    ["foo", "bar"]
  );
});

test("highlighting can mark obfuscated matches", () => {
  assert.equal(buildHighlightedText("stop f o o b a r now", "foobar"), "stop ***f o o b a r*** now");
});

test("highlighting can mark multiple matches", () => {
  assert.equal(buildHighlightedText("foo and b a r", ["foo", "bar"]), "***foo*** and ***b a r***");
});

test("action regex can remove multiple plain and spaced matches", () => {
  let processed = normalizeModerationText("foo and b a r");
  for (const word of ["foo", "bar"]) {
    processed = processed.replace(buildActionRegex(word), "");
  }
  assert.equal(processed.replace(/\s+/g, " ").trim(), "and");
});

test("heuristic abuse detects direct personal attacks", () => {
  assert.equal(findHeuristicAbuse("you are such a pathetic loser"), "loser");
});

test("heuristic abuse detects threat phrases", () => {
  assert.equal(findHeuristicAbuse("go die now"), "go die");
});

test("heuristic abuse does not flag neutral adjective use", () => {
  assert.equal(findHeuristicAbuse("that was a stupid bug in my code"), null);
});
