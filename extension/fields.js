// Pure field-classification and layout helpers for the Nuvori content script.
// The rules mirror the Android app's FormClassifier/UsernameFields (web-relevant parts),
// so a page is read the same way on the phone and in the browser.
// This file runs in the extension's isolated world; it never touches the network,
// storage, or credentials.
// eslint-disable-next-line no-unused-vars
var NuvoriFields = (() => {
  // Qualifiers narrow a purpose ("shipping email") but never are one.
  const QUALIFIERS = new Set(["shipping", "billing", "webauthn"]);
  const USERNAME_HINTS = new Set(["username", "newusername", "emailaddress", "email"]);
  const USERNAME_NAMES = new Set(["username", "email", "emailaddress", "login", "loginemail", "loginusername", "userid",
    "user", "loginid", "loginname", "accountname", "account", "usernameoremail", "emailorusername", "emailorphone",
    "phoneoremail", "identifier", "signinid", "jusername", "sessionusernameoremail"]);
  const NEGATIVE_TOKENS = ["search", "confirm", "verify", "otp", "code", "coupon", "promo", "message", "comment",
    "first", "last", "full", "nick", "display", "refer", "billing", "shipping",
    // Sign-in screens often ask for a server or workspace before the password; that box is not the account.
    "server", "workspace", "domain", "host", "tenant", "company", "organization", "organisation", "captcha", "website"];
  const SECRET_TOKENS = ["password", "passwd", "pwd", "passcode"];
  const OTP_HINTS = new Set(["onetimecode", "2faappotpcode"]);
  const OTP_NAMES = new Set(["otp", "totp", "otpcode", "totpcode", "onetimecode", "onetimepassword", "twofactor",
    "twofactorcode", "2fa", "2facode", "mfa", "mfacode", "authcode", "authenticationcode", "authenticatorcode",
    "verificationcode", "approvalscode"]);
  const NEW_WORDS = ["new", "confirm", "repeat", "retype", "verify", "again"];
  const CONFIRM_WORDS = ["confirm", "repeat", "retype", "verify", "again"];
  const CURRENT_WORDS = ["current", "old", "existing"];
  const ACCOUNT_TYPES = new Set(["", "text", "email"]);
  const OTP_TYPES = new Set(["", "text", "tel", "number", "password"]);

  const normalize = (value) => String(value ?? "").toLowerCase().replace(/[^a-z0-9]/g, "");
  const attr = (input, name) => {
    const value = input?.getAttribute?.(name);
    return typeof value === "string" ? value : typeof input?.[name] === "string" ? input[name] : "";
  };
  const typeOf = (input) => String(input?.type ?? attr(input, "type")).trim().toLowerCase();
  const names = (input) => [attr(input, "name"), attr(input, "id")].filter(Boolean);

  /** Autocomplete tokens: lower-case, split on whitespace, qualifiers and section-* dropped. */
  function purposeTokens(input) {
    const source = attr(input, "autocomplete") || String(input?.autocomplete || "");
    return source.toLowerCase().split(/\s+/).filter((token) => token && !QUALIFIERS.has(token) && !token.startsWith("section-"));
  }
  const purposes = (input) => purposeTokens(input).map(normalize).filter(Boolean);
  const explicitPurposes = (input) => purposes(input).filter((token) => token !== "on" && token !== "off");
  const hasNegative = (texts, negatives = [...NEGATIVE_TOKENS, ...SECRET_TOKENS]) =>
    texts.map(normalize).some((text) => text && negatives.some((word) => text.includes(word)));

  /** USERNAME | PASSWORD | NEW_PASSWORD | OTP | null for one input (ignores visibility). */
  function roleOf(input) {
    if (!input) return null;
    const type = typeOf(input);
    // Hidden inputs are never fields the user sees; card details are never a login.
    if (type === "hidden") return null;
    const norm = purposes(input);
    if (norm.some((token) => token.startsWith("cc") || token.startsWith("creditcard"))) return null;
    if (norm.includes("newpassword")) return "NEW_PASSWORD";
    if (norm.some((token) => OTP_HINTS.has(token))) return "OTP";
    if (norm.includes("password") || norm.includes("currentpassword")) return "PASSWORD";
    // A masked code box is still a code: its name wins over its input type.
    if (!explicitPurposes(input).length && OTP_TYPES.has(type) && names(input).some((name) => OTP_NAMES.has(normalize(name)))) return "OTP";
    if (type === "password") return "PASSWORD";
    if (isUsernameField(input)) return "USERNAME";
    return null;
  }

  /** Recognize account identifiers without guessing from arbitrary text fields. */
  function isUsernameField(input) {
    const type = typeOf(input);
    if (!ACCOUNT_TYPES.has(type)) return false;
    const norm = purposes(input);
    if (norm.some((token) => token.startsWith("cc") || token.startsWith("creditcard"))) return false;
    if (norm.some((token) => USERNAME_HINTS.has(token)) || type === "email") return true;
    // An explicit purpose such as one-time-code, name or tel takes precedence.
    if (explicitPurposes(input).length) return false;
    return names(input).some((name) => USERNAME_NAMES.has(normalize(name)));
  }

  function isPasswordField(input) {
    const role = roleOf(input);
    return role === "PASSWORD" || role === "NEW_PASSWORD";
  }

  function isNewPassword(input) {
    return roleOf(input) === "NEW_PASSWORD";
  }

  function kindOf(input) {
    const norm = purposes(input);
    if (norm.includes("newpassword")) return "NEW";
    if (norm.includes("currentpassword")) return "CURRENT";
    const list = names(input).map(normalize).filter(Boolean);
    if (list.some((name) => NEW_WORDS.some((word) => name.includes(word)) || name.endsWith("2"))) return "NEW";
    if (list.some((name) => CURRENT_WORDS.some((word) => name.includes(word)))) return "CURRENT";
    return "PLAIN";
  }

  const confirmsPassword = (input) => names(input).map(normalize)
    .some((name) => name && (CONFIRM_WORDS.some((word) => name.includes(word)) || name.endsWith("2")));

  /**
   * Split password fields into { current, fresh } using only unambiguous shapes:
   * a lone field, registration (password + confirmation), or change (current + new + confirmation).
   * Returns null for anything else, including a plain password beside one marked only as new.
   */
  function splitPasswords(secrets) {
    const kinds = secrets.map(kindOf);
    if (secrets.length === 1) return kinds[0] === "NEW" ? { current: null, fresh: secrets } : { current: secrets[0], fresh: [] };
    if (secrets.length === 2) {
      if (kinds[1] !== "NEW") return null;
      if (kinds[0] === "CURRENT") return { current: secrets[0], fresh: [secrets[1]] };
      if (kinds[0] === "NEW" || confirmsPassword(secrets[1])) return { current: null, fresh: secrets };
      return null;
    }
    if (secrets.length === 3 && kinds[1] === "NEW" && kinds[2] === "NEW" && kinds[0] !== "NEW") {
      return { current: secrets[0], fresh: secrets.slice(1) };
    }
    return null;
  }

  /** The plain input just before a lone password, when nothing in its form is recognizably the account. */
  function precedingAccount(members, password) {
    for (let index = members.indexOf(password) - 1; index >= 0; index--) {
      const candidate = members[index];
      if (roleOf(candidate) === "OTP") return null;
      if (explicitPurposes(candidate).length || hasNegative(names(candidate))) return null;
      // Many sites sign in with a phone number or an e-mail; a name or address part is never the account.
      const detail = profileRoleOf(candidate);
      if (detail && detail !== "phone" && detail !== "email") return null;
      return ACCOUNT_TYPES.has(typeOf(candidate)) ? candidate : null;
    }
    return null;
  }

  const isPin = (input) => {
    const mode = attr(input, "inputmode").toLowerCase();
    const pattern = attr(input, "pattern");
    return mode === "numeric" || mode === "decimal" || /^(\\d|\[0-9\])[*+{]/.test(pattern);
  };

  /**
   * Classify the credential form the user is working in.
   * `inputs`: inputs in document order. `options.live(input)`: visible and enabled.
   * `options.groupOf(input)`: the input's form (or null outside a form). `options.focused`: breaks ties.
   * Returns { kind, username, password, fresh, otp, pin } or null when unsure.
   * kind: "login" | "register" | "change" | "username" | "otp".
   */
  function classifyForm(inputs, { live = () => true, groupOf = (input) => input?.form ?? null, focused = null } = {}) {
    const items = inputs.filter((input) => input === focused || live(input)).map((input) => ({ input, role: roleOf(input), group: groupOf(input) }));
    const credentialGroups = [...new Set(items.filter((item) => ["PASSWORD", "NEW_PASSWORD", "OTP"].includes(item.role)).map((item) => item.group))];
    if (!credentialGroups.length) {
      // A username-only step (password on the next page): exactly one candidate.
      const only = items.filter((item) => item.role === "USERNAME");
      return only.length === 1 ? { kind: "username", username: only[0].input, password: null, fresh: [], otp: null, pin: false } : null;
    }
    let group = credentialGroups[0];
    if (credentialGroups.length > 1) {
      // Several forms hold credentials (sign-in plus sign-up, say): only the focused one is safe.
      const focusedGroup = focused ? groupOf(focused) : undefined;
      if (focusedGroup === undefined || !credentialGroups.includes(focusedGroup)) return null;
      group = focusedGroup;
    }
    const members = items.filter((item) => item.group === group);
    const secrets = members.filter((item) => item.role === "PASSWORD" || item.role === "NEW_PASSWORD").map((item) => item.input);
    const codes = members.filter((item) => item.role === "OTP").map((item) => item.input);
    const usernames = members.filter((item) => item.role === "USERNAME").map((item) => item.input);
    if (codes.length > 1) return null;
    // Separate one-time-code screens only: never mix factors in one fill.
    if (codes.length) return !secrets.length && !usernames.length ? { kind: "otp", username: null, password: null, fresh: [], otp: codes[0], pin: false } : null;
    const split = splitPasswords(secrets);
    if (!split) return null;
    const order = members.map((item) => item.input);
    const anchor = order.indexOf(secrets[0]);
    let username = null;
    for (const candidate of usernames) if (order.indexOf(candidate) < anchor) username = candidate;
    if (!username && usernames.length === 1) username = usernames[0];
    if (!username && !usernames.length && secrets.length === 1 && split.current) username = precedingAccount(order, split.current);
    const kind = split.current && split.fresh.length ? "change" : split.current ? "login" : "register";
    return { kind, username, password: split.current, fresh: split.fresh, otp: null, pin: Boolean(split.current && isPin(split.current)) };
  }

  /**
   * Decide whether focusing `focused` should offer saved logins: "password", "username",
   * "username-step" (identifier-first page, no password yet), or null.
   */
  function suggestionKind(focused, inputs, options = {}) {
    const form = classifyForm(inputs, { ...options, focused });
    if (!form || !focused) return null;
    if (form.kind === "username") return form.username === focused ? "username-step" : null;
    if (form.kind !== "login" && form.kind !== "change") return null;
    if (focused === form.password) return "password";
    if (focused === form.username) return "username";
    return null;
  }

  /** The username and password fields Nuvori should fill for the focused field. */
  function pairFields(focused, inputs, options = {}) {
    const form = classifyForm(inputs, { ...options, focused });
    if (!form) return { username: null, password: null };
    if (form.kind === "username") return { username: form.username === focused ? focused : null, password: null };
    if (form.kind !== "login" && form.kind !== "change") return { username: null, password: null };
    if (focused !== form.password && focused !== form.username) return { username: null, password: null };
    return { username: form.username, password: form.password };
  }

  /**
   * Read the login a user just submitted from one form's inputs. Returns { username, password } or null.
   * New-password fields win (registration or change); confirmations must match.
   */
  function pickCaptureFields(inputs, live = () => true, { allowPasswordOnly = false } = {}) {
    const form = classifyForm(inputs, { live: (input) => !input.disabled && live(input), groupOf: () => null });
    if (!form || !["login", "register", "change"].includes(form.kind)) return null;
    const candidates = form.fresh.length ? form.fresh : [form.password];
    const password = candidates[0]?.value;
    if (typeof password !== "string" || !password || candidates.some((input) => input.value !== password)) return null;
    let username = typeof form.username?.value === "string" && form.username.value.trim() ? form.username : null;
    // Identifier-first pages often keep the account name in a hidden username field.
    if (!username) username = inputs.find((input) => purposes(input).includes("username") && typeof input.value === "string" && input.value.trim()) || null;
    // Password-only sign-in forms (no account field) can be saved with an empty username, but a
    // numeric PIN with no account field is never a login, and a change or sign-up form without
    // an account field can't say whose password changed.
    if (!username) {
      if (!allowPasswordOnly || form.kind !== "login" || form.pin) return null;
      return password.length > 4096 ? null : { username: "", password };
    }
    const name = username.value.trim();
    if (name.length > 1024 || password.length > 4096) return null;
    return { username: name, password };
  }

  /**
   * The account name a user just entered on an identifier-first page (the password comes on the
   * next page), or "". Only a page whose one credential field is the account name counts.
   */
  function pickUsernameStep(inputs, live = () => true) {
    const form = classifyForm(inputs, { live: (input) => !input.disabled && live(input), groupOf: () => null });
    if (!form || form.kind !== "username") return "";
    const name = typeof form.username?.value === "string" ? form.username.value.trim() : "";
    return name && name.length <= 1024 ? name : "";
  }

  // ---------------------------------------------------------------------------
  // Cards, addresses and one-time codes. Every rule reads the field's own attributes plus the
  // optional label text the caller passes in `labelOf(input)`; nothing here reads the page.

  const CARD_PURPOSES = { ccnumber: "number", ccname: "name", ccgivenname: "name", ccfamilyname: "name",
    ccexp: "exp", ccexpmonth: "expMonth", ccexpyear: "expYear", cccsc: "cvv" };
  const PROFILE_PURPOSES = { name: "name", givenname: "given", familyname: "family", email: "email", tel: "phone",
    telnational: "phone", streetaddress: "address1", addressline1: "address1", addressline2: "address2",
    addressline3: "unit", addresslevel2: "city", addresslevel1: "state", postalcode: "postalCode",
    country: "country", countryname: "country" };
  const TEXT_TYPES = new Set(["", "text", "tel", "email", "number", "search", "select-one", "textarea", "url"]);
  const NOT_DETAILS = /search|coupon|promo|voucher|gift|captcha|referral|newsletter|comment|message|quantity|qty/;
  const CODE_WORDS = /otp|totp|onetime|2fa|twofa|twofactor|2step|twostep|mfa|authcode|authenticat|verificationcode|verifycode|securitycode|logincode|signincode|6digit|sixdigit|8digit/;
  const AUTHENTICATOR_WORDS = /authenticat|totp|2fa|twofa|twofactor|2step|twostep|mfa/;

  /** Lower-case letters and digits of the field's name, id, placeholder, aria-label, title and label. */
  function fieldText(input, labelOf) {
    const label = typeof labelOf === "function" ? String(labelOf(input) || "") : "";
    return [attr(input, "name"), attr(input, "id"), attr(input, "placeholder"), attr(input, "aria-label"), attr(input, "title"), label]
      .map(normalize).filter(Boolean).join(" ");
  }

  const maxLength = (input) => {
    const value = Number.parseInt(attr(input, "maxlength") || String(input?.maxLength ?? ""), 10);
    return Number.isFinite(value) && value > 0 ? value : 0;
  };

  /** The card part a field holds, or null. `securitycode` alone is a card code only beside a card number. */
  function cardRoleOf(input, labelOf) {
    if (!TEXT_TYPES.has(typeOf(input)) || typeOf(input) === "email") return null;
    for (const token of purposes(input)) if (CARD_PURPOSES[token]) return CARD_PURPOSES[token];
    if (explicitPurposes(input).length) return null;
    const text = fieldText(input, labelOf);
    if (!text || NOT_DETAILS.test(text)) return null;
    if (/cvv|cvc|csc|cvn|cardcode|cardverification|cardsecurity|cvd/.test(text)) return "cvv";
    if (/nameoncard|cardholder|holdername|ccname|cardname|nameoncc/.test(text)) return "name";
    if (/expir|expdate|validthru|validtill|validuntil|ccexp|cardexp|mmyy|mmaa/.test(text)) {
      if (/month|(^|[^m])mm($|[^y])/.test(text) && !/mmyy|year/.test(text)) return "expMonth";
      if (/year|yyyy|(^|[^m])yy$/.test(text) && !/mmyy|month/.test(text)) return "expYear";
      return "exp";
    }
    if (/cardnumber|cardno|ccnumber|ccnum|creditcard|debitcard|cardnum|numerodetarjeta|kartennummer|^pan$/.test(text) &&
        !/name|holder|type|brand/.test(text)) return "number";
    return null;
  }

  /** A separate expiry month or year (or a security code) only counts beside a card number. */
  function cardContextRole(input, labelOf) {
    if (!TEXT_TYPES.has(typeOf(input))) return null;
    const text = fieldText(input, labelOf);
    if (/(^|\s)(month|mm|expmonth)(\s|$)|month/.test(text) && !/year/.test(text)) return "expMonth";
    if (/(^|\s)(year|yy|yyyy|expyear)(\s|$)|year/.test(text) && !/month/.test(text)) return "expYear";
    if (/securitycode|securitynumber/.test(text)) return "cvv";
    return null;
  }

  /** The profile part a field holds, or null. */
  function profileRoleOf(input, labelOf) {
    const type = typeOf(input);
    if (!TEXT_TYPES.has(type)) return null;
    for (const token of purposes(input)) {
      if (token.startsWith("cc")) return null;
      if (PROFILE_PURPOSES[token]) return PROFILE_PURPOSES[token];
    }
    if (explicitPurposes(input).length) return null;
    if (type === "email") return "email";
    if (type === "tel") return "phone";
    const text = fieldText(input, labelOf);
    if (!text || NOT_DETAILS.test(text) || /user|login|password|otp|code(?!postal)/.test(text) && !/postcode|zipcode|pincode|postalcode/.test(text)) return null;
    if (/email|emailaddress/.test(text)) return "email";
    if (/phone|mobile|telephone|cellnumber|contactnumber/.test(text)) return "phone";
    if (/fullname|yourname|customername|contactname|recipientname/.test(text)) return "name";
    if (/firstname|(^|\s)fname($|\s)|givenname|forename/.test(text)) return "given";
    if (/lastname|(^|\s)lname($|\s)|surname|familyname/.test(text)) return "family";
    if (/zip|postal|postcode|pincode/.test(text)) return "postalCode";
    if (/country/.test(text)) return "country";
    if (/address2|addressline2|addr2|line2/.test(text)) return "address2";
    // Apartment, suite and unit numbers are their own part, as on the phone (address-line3).
    if (/apartment|suite|(^|\s)apt|(^|\s)unit($|\s|no|number)|flatno|flatnumber|houseno|housenumber|building/.test(text)) return "unit";
    if (/address1|addressline1|addr1|line1|street|^address|address$|shippingaddress|billingaddress/.test(text) && !/email|ip/.test(text)) return "address1";
    if (/city|town|locality/.test(text)) return "city";
    if (/(^|[^a-z])(state|province|region|county)($|[^a-z])|^state|state$|province|region/.test(text) && !/statement/.test(text)) return "state";
    if (/fullname|^name$|^name\s|\sname$|yourname|customername|contactname|recipientname|shippingname|billingname/.test(text)) return "name";
    return null;
  }

  /** True for a one-time-code field: the login classifier's OTP role or code words in its labels. */
  function isCodeField(input, labelOf) {
    if (roleOf(input) === "OTP") return true;
    const type = typeOf(input);
    if (!["", "text", "tel", "number", "password"].includes(type) || explicitPurposes(input).some((token) => token !== "onetimecode")) return false;
    const text = fieldText(input, labelOf);
    return Boolean(text) && CODE_WORDS.test(text) && !NOT_DETAILS.test(text) && !/card|cvv|cvc|zip|postal|pincode/.test(text);
  }

  /** Single-digit boxes in a row (maxlength 1): a split one-time code. */
  function codeBoxes(focused, fields, live = () => true) {
    if (maxLength(focused) !== 1) return [];
    const boxes = fields.filter((input) => input === focused || (live(input) && maxLength(input) === 1 &&
      ["", "text", "tel", "number", "password"].includes(typeOf(input))));
    const index = boxes.indexOf(focused);
    if (index < 0) return [];
    // The run of consecutive boxes that contains the focused one.
    let start = index;
    while (start > 0 && fields.indexOf(boxes[start - 1]) === fields.indexOf(boxes[start]) - 1) start--;
    let end = index;
    while (end < boxes.length - 1 && fields.indexOf(boxes[end + 1]) === fields.indexOf(boxes[end]) + 1) end++;
    const run = boxes.slice(start, end + 1);
    return run.length >= 4 && run.length <= 8 ? run : [];
  }

  /**
   * The card, address and code fields among `fields` (inputs, selects and text areas of one form,
   * in document order). Card fields win over address fields; a code never mixes with either.
   */
  function detailFields(fields, { labelOf, live = () => true } = {}) {
    const card = { number: [], name: null, exp: null, expMonth: null, expYear: null, cvv: null };
    const profile = {};
    const seen = fields.filter((input) => live(input));
    for (const input of seen) {
      const role = cardRoleOf(input, labelOf);
      if (role === "number") card.number.push(input);
      else if (role && !card[role]) card[role] = input;
    }
    if (card.number.length) {
      for (const input of seen) {
        if (card.number.includes(input) || Object.values(card).includes(input)) continue;
        const role = cardContextRole(input, labelOf);
        if (role && !card[role]) card[role] = input;
      }
    }
    const cardInputs = new Set([...card.number, card.name, card.exp, card.expMonth, card.expYear, card.cvv].filter(Boolean));
    for (const input of seen) {
      if (cardInputs.has(input)) continue;
      const role = profileRoleOf(input, labelOf);
      if (role && !profile[role]) profile[role] = input;
    }
    return { card, profile, cardInputs };
  }

  /**
   * What focusing `focused` should offer besides logins: "card", "profile", "code", "code-weak"
   * (a code field without authenticator wording: offer only matching codes) or null.
   */
  function detailKind(focused, fields, options = {}) {
    if (!focused) return null;
    if (isCodeField(focused, options.labelOf) || codeBoxes(focused, fields, options.live).length) {
      return AUTHENTICATOR_WORDS.test(fieldText(focused, options.labelOf)) || purposes(focused).includes("onetimecode") ? "code" : "code-weak";
    }
    const { card, profile, cardInputs } = detailFields(fields, options);
    if (card.number.length && cardInputs.has(focused)) return "card";
    const profileInputs = Object.values(profile);
    if (!profileInputs.includes(focused)) return null;
    // One lone email box is usually a newsletter; an address form has several parts.
    const explicit = purposes(focused).some((token) => PROFILE_PURPOSES[token]);
    return profileInputs.length >= 2 || (explicit && !["email", "phone"].includes(Object.keys(profile).find((key) => profile[key] === focused)))
      ? "profile" : null;
  }

  // ---------------------------------------------------------------------------
  // Card values

  function luhn(digits) {
    if (!/^\d{12,19}$/.test(digits)) return false;
    let sum = 0;
    for (let index = 0; index < digits.length; index++) {
      let digit = Number(digits[digits.length - 1 - index]);
      if (index % 2 === 1) { digit *= 2; if (digit > 9) digit -= 9; }
      sum += digit;
    }
    return sum % 10 === 0;
  }

  /** "MM/YY" from what a page holds ("7/2029", "0729", "07 / 29"), or "". Mirrors the Rust check. */
  function normalizeExpiry(value) {
    const text = String(value ?? "").trim();
    let month; let year;
    const parts = text.split(/\s*[/-]\s*/);
    if (parts.length === 2 && /^\d{1,2}$/.test(parts[0]) && /^\d{2}(\d{2})?$/.test(parts[1])) [month, year] = parts;
    else if (/^\d{4}$|^\d{6}$/.test(text)) { month = text.slice(0, 2); year = text.slice(2); }
    else return "";
    const m = Number(month);
    if (!(m >= 1 && m <= 12)) return "";
    if (year.length === 4) { if (!year.startsWith("20")) return ""; year = year.slice(2); }
    return `${String(m).padStart(2, "0")}/${year}`;
  }

  /** The text to type into a combined expiry field, shaped by its placeholder and length. */
  function expiryText(input, expiry) {
    const [month, year] = String(expiry).split("/");
    if (!month || !year) return "";
    const hint = `${attr(input, "placeholder")} ${attr(input, "aria-label")}`.toLowerCase();
    const max = maxLength(input);
    const full = /yyyy|aaaa|jjjj/.test(hint) || max >= 7 && !/yy/.test(hint) ? `20${year}` : year;
    if (max === 4 || (max && max < 5)) return `${month}${year}`;
    const spaced = /\s\/\s/.test(attr(input, "placeholder"));
    return spaced ? `${month} / ${full}` : `${month}/${full}`;
  }

  /** The option value of `select` (its `options` list) that matches one of `wanted`, or null. */
  function optionValue(select, wanted) {
    const options = [...(select?.options || [])];
    const want = wanted.map((value) => String(value).trim().toLowerCase()).filter(Boolean);
    for (const value of want) {
      const hit = options.find((option) => String(option.value).trim().toLowerCase() === value)
        || options.find((option) => String(option.text ?? option.textContent ?? "").trim().toLowerCase() === value);
      if (hit) return hit.value;
    }
    return null;
  }

  const MONTHS = ["january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "december"];

  /** Values a month field might use for month `mm` ("07"): 07, 7, July, Jul. */
  function monthChoices(mm) {
    const number = Number(mm);
    const name = MONTHS[number - 1] || "";
    return [mm, String(number), name, name.slice(0, 3), `${mm} - ${name}`, `${mm} - ${name.slice(0, 3)}`];
  }

  /** Values a year field might use for "YY": 2029, 29. */
  function yearChoices(yy) {
    return [`20${yy}`, yy];
  }

  /** The number, name and expiry a user just typed into a payment form, never the security code. */
  function pickCardCapture(fields, options = {}) {
    const { card } = detailFields(fields, options);
    if (!card.number.length) return null;
    const digits = card.number.map((input) => String(input.value ?? "")).join("").replace(/[\s-]/g, "");
    if (!luhn(digits)) return null;
    let expiry = card.exp ? normalizeExpiry(card.exp.value) : "";
    if (!expiry && card.expMonth && card.expYear) {
      const month = String(card.expMonth.value ?? "").trim();
      const year = String(card.expYear.value ?? "").trim();
      expiry = normalizeExpiry(`${month}/${year}`);
    }
    const name = String(card.name?.value ?? "").trim().slice(0, 200);
    return { number: digits, name, expiry };
  }

  /** An address the user just submitted: a street plus a city or postal code. */
  function pickProfileCapture(fields, options = {}) {
    const { profile } = detailFields(fields, options);
    const value = (role) => {
      const input = profile[role];
      if (!input) return "";
      const raw = typeOf(input) === "select-one"
        ? String(input.options?.[input.selectedIndex]?.text ?? input.value ?? "")
        : String(input.value ?? "");
      return raw.replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, 256);
    };
    const address1 = value("address1");
    if (!address1 || !(value("city") || value("postalCode"))) return null;
    const name = value("name") || [value("given"), value("family")].filter(Boolean).join(" ");
    return { name, email: value("email"), phone: value("phone"), address1, address2: value("address2"), unit: value("unit"),
      city: value("city"), state: value("state"), postalCode: value("postalCode"), country: value("country") };
  }

  /** Place a dropdown under (or above) a field, clamped to the viewport. */
  function placeDropdown(rect, size, viewport, { gap = 4, margin = 8, minWidth = 280, maxWidth = 360 } = {}) {
    const available = Math.max(0, viewport.width - margin * 2);
    const width = Math.min(Math.max(rect.width, minWidth), maxWidth, available);
    const left = Math.min(Math.max(rect.left, margin), Math.max(margin, viewport.width - width - margin));
    const below = rect.bottom + gap;
    const spaceBelow = viewport.height - below - margin;
    const spaceAbove = rect.top - gap - margin;
    const placement = size.height <= spaceBelow || spaceBelow >= spaceAbove ? "below" : "above";
    let top = placement === "below" ? below : rect.top - gap - size.height;
    top = Math.min(Math.max(top, margin), Math.max(margin, viewport.height - size.height - margin));
    return { top: Math.round(top), left: Math.round(left), width: Math.round(width), placement };
  }

  /** True when a field's box is not collapsed and is at least partly inside the viewport horizontally. */
  function boxIsUsable(rect, viewport) {
    if (!rect || rect.width < 4 || rect.height < 4) return false;
    return rect.right > 0 && rect.left < viewport.width;
  }

  return {
    roleOf, isUsernameField, isPasswordField, isNewPassword, splitPasswords, classifyForm,
    suggestionKind, pairFields, pickCaptureFields, pickUsernameStep, placeDropdown, boxIsUsable,
    cardRoleOf, profileRoleOf, isCodeField, codeBoxes, detailFields, detailKind,
    luhn, normalizeExpiry, expiryText, optionValue, monthChoices, yearChoices, pickCardCapture, pickProfileCapture,
  };
})();
