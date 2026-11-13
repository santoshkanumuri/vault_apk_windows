import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";

const context = vm.createContext({ URL });
vm.runInContext(readFileSync(new URL("./fields.js", import.meta.url), "utf8"), context);
const F = context.NuvoriFields;

let nextId = 0;
function input(type = "text", attrs = {}, value = "") {
  const node = { type, value, disabled: false, form: attrs.form ?? null, key: attrs.key ?? `field-${++nextId}` };
  const attributes = { ...attrs };
  delete attributes.form;
  delete attributes.key;
  node.getAttribute = (name) => (name in attributes ? attributes[name] : null);
  node.autocomplete = attributes.autocomplete || "";
  return node;
}

test("autocomplete hints are case-insensitive and ignore section, shipping, billing and webauthn qualifiers", () => {
  assert.equal(F.roleOf(input("text", { autocomplete: "section-login USERNAME" })), "USERNAME");
  assert.equal(F.roleOf(input("text", { autocomplete: "username webauthn" })), "USERNAME");
  assert.equal(F.roleOf(input("password", { autocomplete: "Current-Password" })), "PASSWORD");
  assert.equal(F.roleOf(input("password", { autocomplete: "section-a New-Password" })), "NEW_PASSWORD");
  assert.equal(F.roleOf(input("email", { autocomplete: "billing email" })), "USERNAME");
});

test("hidden inputs and card fields never count", () => {
  assert.equal(F.roleOf(input("hidden", { autocomplete: "username" }, "alice")), null);
  assert.equal(F.roleOf(input("password", { autocomplete: "cc-csc" })), null);
  assert.equal(F.roleOf(input("text", { autocomplete: "cc-number" })), null);
  assert.equal(F.roleOf(input("text", { name: "search" })), null);
  assert.equal(F.roleOf(input("text", { name: "login_email" })), "USERNAME");
  assert.equal(F.roleOf(input("text", { name: "otp" })), "OTP");
  assert.equal(F.roleOf(input("text", { name: "email", autocomplete: "tel" })), null, "an explicit purpose wins over the name");
});

test("a plain sign-in form pairs the account with the password from either field", () => {
  const user = input("email");
  const pass = input("password");
  const fields = [input("text", { name: "q" }), user, pass];
  assert.equal(F.suggestionKind(user, fields), "username");
  assert.equal(F.suggestionKind(pass, fields), "password");
  const pair = F.pairFields(user, fields);
  assert.equal(pair.username, user);
  assert.equal(pair.password, pass);
});

test("a lone password falls back to the nearest preceding plain input as the username", () => {
  const plain = input("text", { name: "acct" });
  const pass = input("password");
  assert.equal(F.pairFields(pass, [plain, pass]).username, plain);
  assert.equal(F.pairFields(pass, [input("text", { name: "promo_code" }), pass]).username, null, "a named non-account field is never guessed");
});

test("a server, workspace or captcha box before a lone password is not the username (Android NEGATIVE_TOKENS)", () => {
  const pass = input("password");
  for (const name of ["server", "workspace", "domain", "host_name", "tenant", "company", "organization", "organisation", "captcha", "website"]) {
    assert.equal(F.pairFields(pass, [input("text", { name }), pass]).username, null, name);
    assert.equal(F.pickCaptureFields([input("text", { name }, "acme"), input("password", {}, "secret")]), null, `${name} is never saved as a username`);
  }
});

test("the box before a lone password is read as the vectors shared with the Android app say", () => {
  const { cases } = JSON.parse(readFileSync(new URL("./fixtures/preceding-account-v1.json", import.meta.url), "utf8"));
  assert.ok(cases.length > 0);
  for (const { name, username } of cases) {
    const field = input("text", { name });
    const pass = input("password");
    const pair = F.pairFields(pass, [field, pass]);
    assert.equal(pair.password, pass, name);
    assert.equal(pair.username, username ? field : null, name);
  }
});

test("an identifier-first page gives its account name; a sign-in form or an empty box gives nothing", () => {
  assert.equal(F.pickUsernameStep([input("email", {}, " bob@example.com ")]), "bob@example.com");
  assert.equal(F.pickUsernameStep([input("email", {}, "")]), "");
  assert.equal(F.pickUsernameStep([input("email", {}, "bob"), input("password", {}, "secret")]), "", "a password form is a capture, not a step");
  assert.equal(F.pickUsernameStep([input("email", {}, "a"), input("email", {}, "b")]), "", "two account boxes are ambiguous");
  assert.equal(F.pickUsernameStep([input("text", { name: "q" }, "search words")]), "");
});

test("code and address fields are read as the vectors shared with the Android app say", () => {
  const { cases } = JSON.parse(readFileSync(new URL("./fixtures/field-roles-v1.json", import.meta.url), "utf8"));
  assert.ok(cases.length > 0);
  const failures = [];
  for (const { name, autocomplete, role } of cases) {
    const attrs = {};
    if (name !== undefined) attrs.name = name;
    if (autocomplete !== undefined) attrs.autocomplete = autocomplete;
    const field = input("", attrs);
    const actual = F.roleOf(field) === "OTP" ? "code" : F.profileRoleOf(field);
    if (actual !== role) failures.push(`${JSON.stringify(attrs)}: expected ${role}, got ${actual}`);
  }
  assert.deepEqual(failures, []);
});

test("with several credential forms, the focused one wins; without focus nothing is chosen", () => {
  const login = {}, signup = {};
  const loginUser = input("email", { form: login });
  const loginPass = input("password", { form: login });
  const signupUser = input("email", { form: signup });
  const signupPass = input("password", { form: signup, autocomplete: "new-password" });
  const fields = [loginUser, loginPass, signupUser, signupPass];
  assert.equal(F.classifyForm(fields), null);
  assert.equal(F.pairFields(loginPass, fields).username, loginUser);
  assert.equal(F.suggestionKind(signupUser, fields), null, "a registration form offers no saved logins");
});

test("registration, change and ambiguous password shapes", () => {
  const registration = [input("email"), input("password", { name: "password" }), input("password", { name: "password_confirmation" })];
  assert.equal(F.classifyForm(registration).kind, "register");
  const change = [input("password", { name: "current_password" }), input("password", { name: "new_password" }), input("password", { name: "confirm_password" })];
  const changed = F.classifyForm(change);
  assert.equal(changed.kind, "change");
  assert.equal(changed.password, change[0]);
  assert.equal(F.suggestionKind(change[1], change), null, "never fill a saved password into a new-password box");
  const ambiguous = [input("email"), input("password", { name: "pw" }), input("password", { autocomplete: "new-password" })];
  assert.equal(F.classifyForm(ambiguous), null);
  assert.deepEqual({ ...F.pairFields(ambiguous[1], ambiguous) }, { username: null, password: null });
});

test("one-time-code screens and mixed factors are not login forms", () => {
  const code = input("text", { autocomplete: "one-time-code" });
  assert.equal(F.classifyForm([code]).kind, "otp");
  assert.equal(F.suggestionKind(code, [code]), null);
  const mixed = [input("email"), input("password"), input("text", { name: "totp" })];
  assert.equal(F.classifyForm(mixed), null);
});

test("an identifier-first step is recognized only with exactly one account field", () => {
  const user = input("text", { autocomplete: "username" });
  assert.equal(F.suggestionKind(user, [user]), "username-step");
  assert.deepEqual({ ...F.pairFields(user, [user]) }, { username: user, password: null });
  const a = input("email"), b = input("email");
  assert.equal(F.suggestionKind(a, [a, b]), null);
});

test("capture takes matching new passwords, rejects mismatches, and skips a PIN with no account", () => {
  const user = input("email", {}, "synthetic-user");
  const current = input("password", {}, "old-password");
  const fresh = input("password", { autocomplete: "new-password" }, "new-password");
  const confirm = input("password", { autocomplete: "new-password" }, "different");
  assert.equal(F.pickCaptureFields([user, current, fresh, confirm]), null);
  confirm.value = "new-password";
  assert.deepEqual({ ...F.pickCaptureFields([user, current, fresh, confirm]) }, { username: "synthetic-user", password: "new-password" });
  assert.equal(F.pickCaptureFields([input("password", { inputmode: "numeric" }, "1234")]), null);
  const hiddenUser = input("hidden", { autocomplete: "username" }, "first-step-user");
  assert.equal(F.pickCaptureFields([hiddenUser, input("password", {}, "secret")]).username, "first-step-user");
  assert.equal(F.pickCaptureFields([input("email", {}, "u"), input("password", {}, "x".repeat(4097))]), null);
});

test("the dropdown sits under the field, flips above near the bottom, and stays in the viewport", () => {
  const viewport = { width: 400, height: 600 };
  const below = F.placeDropdown({ left: 20, top: 100, bottom: 140, width: 200 }, { height: 150 }, viewport);
  assert.deepEqual({ ...below }, { top: 144, left: 20, width: 280, placement: "below" });
  const above = F.placeDropdown({ left: 20, top: 500, bottom: 540, width: 200 }, { height: 150 }, viewport);
  assert.equal(above.placement, "above");
  assert.equal(above.top, 346);
  const clamped = F.placeDropdown({ left: 300, top: 100, bottom: 140, width: 300 }, { height: 100 }, viewport);
  assert.equal(clamped.left + clamped.width <= viewport.width - 8, true);
  const narrow = F.placeDropdown({ left: 0, top: 10, bottom: 40, width: 300 }, { height: 100 }, { width: 200, height: 300 });
  assert.equal(narrow.width, 184);
  assert.equal(F.boxIsUsable({ left: -500, right: -100, width: 400, height: 30 }, viewport), false);
  assert.equal(F.boxIsUsable({ left: 10, right: 12, width: 2, height: 30 }, viewport), false);
});

test("password-only capture: sign-in forms only, never a PIN, change or sign-up form", () => {
  const lone = input("password", {}, "secret");
  assert.equal(F.pickCaptureFields([lone]), null, "off unless the host supports it");
  assert.deepEqual({ ...F.pickCaptureFields([lone], () => true, { allowPasswordOnly: true }) }, { username: "", password: "secret" });
  assert.equal(F.pickCaptureFields([input("password", { inputmode: "numeric" }, "1234")], () => true, { allowPasswordOnly: true }), null);
  const change = [input("password", { name: "current_password" }, "old"), input("password", { name: "new_password" }, "n"), input("password", { name: "confirm_password" }, "n")];
  assert.equal(F.pickCaptureFields(change, () => true, { allowPasswordOnly: true }), null);
  const signup = [input("password", { name: "password" }, "n"), input("password", { name: "password_confirmation" }, "n")];
  assert.equal(F.pickCaptureFields(signup, () => true, { allowPasswordOnly: true }), null);
  const named = [input("email", {}, "u@example.com"), input("password", {}, "secret")];
  assert.equal(F.pickCaptureFields(named, () => true, { allowPasswordOnly: true }).username, "u@example.com", "an account field still wins");
});

// ---------------------------------------------------------------------------
// Cards, addresses and one-time codes

const select = (attrs, options, value = "") => {
  const node = input("select-one", attrs, value);
  node.options = options.map(([optionValue, text]) => ({ value: optionValue, text }));
  node.selectedIndex = Math.max(0, node.options.findIndex((option) => option.value === value));
  return node;
};
const labels = (map) => (node) => map.get(node) || "";

test("card fields: autocomplete, names and labels; security code only beside a card number", () => {
  assert.equal(F.cardRoleOf(input("text", { autocomplete: "cc-number" })), "number");
  assert.equal(F.cardRoleOf(input("text", { autocomplete: "billing cc-exp" })), "exp");
  assert.equal(F.cardRoleOf(input("tel", { name: "cardNumber" })), "number");
  assert.equal(F.cardRoleOf(input("text", { id: "cvc" })), "cvv");
  assert.equal(F.cardRoleOf(input("text", { placeholder: "MM / YY" })), "exp");
  assert.equal(F.cardRoleOf(input("text", { name: "exp-month" }), () => "Expiry month"), "expMonth");
  assert.equal(F.cardRoleOf(input("text", { name: "holder" }), () => "Name on card"), "name");
  assert.equal(F.cardRoleOf(input("text", { name: "coupon_code" })), null);
  const number = input("tel", { name: "card_number" });
  const month = select({ name: "month" }, [["", "Month"], ["01", "01"], ["07", "07"]]);
  const year = select({ name: "year" }, [["", "Year"], ["2029", "2029"]]);
  const code = input("tel", { name: "security_code" });
  const { card } = F.detailFields([number, month, year, code]);
  assert.deepEqual([card.number[0], card.expMonth, card.expYear, card.cvv], [number, month, year, code]);
  assert.equal(F.detailFields([input("text", { name: "month" })]).card.expMonth, null, "no card number, no card");
  assert.equal(F.detailKind(month, [number, month, year, code]), "card");
});

test("address fields need two parts unless the page says so explicitly", () => {
  const name = input("text", { name: "fullName" });
  const street = input("text", {}, "");
  const city = input("text", { name: "city" });
  const pin = input("text", { name: "pincode" });
  const map = new Map([[street, "Street address"]]);
  const options = { labelOf: labels(map) };
  const { profile } = F.detailFields([name, street, city, pin], options);
  assert.deepEqual([profile.name, profile.address1, profile.city, profile.postalCode], [name, street, city, pin]);
  assert.equal(F.detailKind(city, [name, street, city, pin], options), "profile");
  const newsletter = input("email", { name: "newsletter_email" });
  assert.equal(F.detailKind(newsletter, [newsletter]), null, "a lone email box stays quiet");
  const lone = input("text", { autocomplete: "postal-code" });
  assert.equal(F.detailKind(lone, [lone]), "profile");
  assert.equal(F.profileRoleOf(input("text", { name: "username" })), null);
  assert.equal(F.profileRoleOf(input("text", { name: "statement_month" })), null);
  assert.equal(F.profileRoleOf(input("text", { name: "first_name" })), "given");
});

test("one-time codes: names, labels, and split digit boxes; authenticator wording is strong", () => {
  assert.equal(F.isCodeField(input("text", { autocomplete: "one-time-code" })), true);
  assert.equal(F.isCodeField(input("text", { name: "verification_code" })), true);
  assert.equal(F.isCodeField(input("tel", {}), () => "Enter the 6-digit code from your authenticator app"), true);
  assert.equal(F.isCodeField(input("text", { name: "promo_code" })), false);
  assert.equal(F.isCodeField(input("text", { name: "zip_code" })), false);
  const strong = input("text", { name: "totp" });
  assert.equal(F.detailKind(strong, [strong]), "code");
  const weak = input("text", { name: "verification_code" });
  assert.equal(F.detailKind(weak, [weak]), "code-weak");
  const boxes = Array.from({ length: 6 }, () => input("tel", { maxlength: "1", inputmode: "numeric" }));
  const before = input("text", { name: "other" });
  assert.equal(F.codeBoxes(boxes[2], [before, ...boxes]).length, 6);
  assert.equal(F.codeBoxes(boxes[2], [before, ...boxes.slice(0, 3)]).length, 0, "fewer than four is not a code");
  assert.equal(F.detailKind(boxes[0], boxes), "code-weak");
});

test("card values: Luhn, expiry shapes, select options", () => {
  assert.equal(F.luhn("4111111111111111"), true);
  assert.equal(F.luhn("4111111111111112"), false);
  assert.equal(F.normalizeExpiry("7/2029"), "07/29");
  assert.equal(F.normalizeExpiry("0729"), "07/29");
  assert.equal(F.normalizeExpiry("13/29"), "");
  assert.equal(F.expiryText(input("text", { placeholder: "MM/YY" }), "07/29"), "07/29");
  assert.equal(F.expiryText(input("text", { placeholder: "MM / YYYY" }), "07/29"), "07 / 2029");
  assert.equal(F.expiryText(input("text", { maxlength: "4" }), "07/29"), "0729");
  const months = select({}, [["", "Month"], ["1", "January"], ["7", "July"]]);
  assert.equal(F.optionValue(months, F.monthChoices("07")), "7");
  const named = select({}, [["jan", "Jan"], ["jul", "Jul"]]);
  assert.equal(F.optionValue(named, F.monthChoices("07")), "jul");
  const years = select({}, [["29", "2029"]]);
  assert.equal(F.optionValue(years, F.yearChoices("29")), "29");
  assert.equal(F.optionValue(years, ["2031"]), null);
});

test("captures: a valid card without its code, and an address with a street and city", () => {
  const number = input("tel", { autocomplete: "cc-number" }, "4111 1111 1111 1111");
  const exp = input("text", { autocomplete: "cc-exp" }, "7 / 29");
  const name = input("text", { autocomplete: "cc-name" }, "A Person");
  const cvv = input("text", { autocomplete: "cc-csc" }, "123");
  assert.deepEqual({ ...F.pickCardCapture([number, exp, name, cvv]) }, { number: "4111111111111111", name: "A Person", expiry: "07/29" });
  assert.equal(F.pickCardCapture([input("tel", { autocomplete: "cc-number" }, "4111111111111112")]), null);
  const split = [1, 2, 3, 4].map((part) => input("tel", { name: `card_number_${part}` }, part === 1 ? "4111" : "1111"));
  assert.equal(F.pickCardCapture(split).number, "4111111111111111");

  const street = input("text", { autocomplete: "address-line1" }, "1 Main Road");
  const city = input("text", { autocomplete: "address-level2" }, "Pune");
  const country = select({ autocomplete: "country" }, [["IN", "India"], ["US", "United States"]], "IN");
  const given = input("text", { autocomplete: "given-name" }, "A");
  const family = input("text", { autocomplete: "family-name" }, "Person");
  const address = F.pickProfileCapture([given, family, street, city, country]);
  assert.equal(address.name, "A Person");
  assert.equal(address.country, "India");
  assert.equal(address.city, "Pune");
  assert.equal(F.pickProfileCapture([given, family]), null, "a name alone is not an address");
});
