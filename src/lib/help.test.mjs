// Run with `npm test`. Node strips the TypeScript types of help.ts on load.
import { test } from "node:test";
import assert from "node:assert/strict";
import { helpSections, helpTopics, searchHelp } from "./help.ts";

/** Every page a help shortcut may open. A typo here would be a button that goes nowhere. */
const PAGES = ["home", "codes", "signins", "notes", "sync", "settings", "activity", "trash", "more"];
const SETTINGS_SECTIONS = ["security", "browser", "devices", "appearance", "colors", "data", "about", "danger"];

test("every answer is a question with an answer and a section", () => {
  assert.ok(helpTopics.length > 10, "the page is worth opening");
  for (const topic of helpTopics) {
    assert.ok(topic.section.trim(), `a section heading: ${topic.question}`);
    assert.ok(topic.question.trim().endsWith("?"), `a question, not a title: ${topic.question}`);
    assert.ok(topic.answer.trim().length > 40, `an answer worth reading: ${topic.question}`);
    assert.ok(!/\n/.test(topic.answer), `one paragraph: ${topic.question}`);
  }
  const questions = helpTopics.map((topic) => topic.question);
  assert.equal(new Set(questions).size, questions.length, "no question is asked twice");
});

test("a shortcut points at a screen this app has", () => {
  for (const { question, go } of helpTopics) {
    if (!go) continue;
    assert.ok(go.label.trim(), `a label for the shortcut: ${question}`);
    assert.ok(PAGES.includes(go.route.page), `${go.route.page} is a page (${question})`);
    if (go.route.page === "settings" && go.route.section)
      assert.ok(SETTINGS_SECTIONS.includes(go.route.section), `settings-${go.route.section} exists (${question})`);
  }
  assert.ok(helpTopics.filter((topic) => topic.go).length > helpTopics.length / 2, "most answers end somewhere useful");
});

test("the questions of one section stay together", () => {
  const sections = helpSections();
  assert.deepEqual(sections, [...new Set(sections)], "a section is listed once");
  let last = -1;
  for (const topic of helpTopics) {
    const at = sections.indexOf(topic.section);
    assert.ok(at >= last, `${topic.section} is not split apart by another section`);
    last = at;
  }
  assert.deepEqual(helpSections([helpTopics[2], helpTopics[0]]).length, new Set([helpTopics[2].section, helpTopics[0].section]).size);
});

test("searching needs every word, in the question, the answer or the heading", () => {
  assert.equal(searchHelp("").length, helpTopics.length, "no search shows everything");
  assert.equal(searchHelp("   ").length, helpTopics.length);

  const unlock = searchHelp("unlock");
  assert.ok(unlock.length >= 2, "several answers mention unlocking");
  assert.ok(unlock.every((topic) => /unlock/i.test(`${topic.section} ${topic.question} ${topic.answer}`)));

  // A word only in the answer still finds it: no question says "Hello".
  assert.ok(!helpTopics.some((topic) => /hello/i.test(topic.question)));
  const hello = searchHelp("hello");
  assert.ok(hello.length >= 1 && hello.every((topic) => /hello/i.test(topic.answer)), "Windows Hello is findable");
  assert.ok(hello.some((topic) => /fingerprint/i.test(topic.question)), "and it is the unlock answer");

  // A word only in the heading finds the section.
  assert.ok(searchHelp("passkeys").length >= 2);

  // More words narrow, and the order of what is left is the page's own.
  const wide = searchHelp("password");
  const narrow = searchHelp("password forgot");
  assert.ok(narrow.length >= 1 && narrow.length < wide.length, "a second word narrows the list");
  assert.deepEqual(narrow, wide.filter((topic) => narrow.includes(topic)), "matches keep the page's order");

  assert.deepEqual(searchHelp("kangaroo"), [], "nothing matches a word that isn't there");
  assert.deepEqual(searchHelp("unlock kangaroo"), [], "every word has to match");
});

test("case is ignored, as in the vault's search", () => {
  assert.deepEqual(searchHelp("KEEPASS"), searchHelp("keepass"));
  assert.ok(searchHelp("KeePass").length >= 1);
  assert.deepEqual(searchHelp("Google DRIVE"), searchHelp("google drive"));
  assert.ok(searchHelp("google drive").length >= 2);
});
