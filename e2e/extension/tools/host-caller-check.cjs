// Checks which callers the real native host accepts, against a throwaway LOCALAPPDATA.
const { spawnSync } = require("child_process");
const fs = require("fs"), os = require("os"), path = require("path");
const root = fs.mkdtempSync(path.join(os.tmpdir(), "nuvori-host-"));
const dir = path.join(root, "Nuvori", "BrowserHost");
fs.mkdirSync(dir, { recursive: true });
const ff = path.join(dir, "com.nuvori.desktop.firefox.json");
fs.writeFileSync(ff, JSON.stringify({ name: "com.nuvori.desktop", path: "x", type: "stdio", allowed_extensions: ["password-fill@nuvori.santoshkanumuri.com"] }));
fs.writeFileSync(path.join(dir, "com.nuvori.desktop.json"), JSON.stringify({ name: "com.nuvori.desktop", path: "x", type: "stdio", allowed_origins: ["chrome-extension://kapellkbongejlglcengbmjnpblemmjm/"] }));
const exe = path.resolve(process.argv[2]);
const body = Buffer.from(JSON.stringify({ version: 2, requestId: "1", action: "status", origin: "" }));
const head = Buffer.alloc(4); head.writeUInt32LE(body.length);
const run = (label, args, expectReply) => {
  const r = spawnSync(exe, args, { input: Buffer.concat([head, body]), env: { ...process.env, LOCALAPPDATA: root }, timeout: 15000 });
  const reply = r.stdout.length > 4 ? JSON.parse(r.stdout.subarray(4).toString()).status : null;
  const ok = expectReply ? Boolean(reply) : !reply;
  console.log(`${ok ? "PASS" : "FAIL"} ${label.padEnd(40)} exit=${r.status} reply=${reply ?? "(refused)"}`);
  return ok;
};
const results = [
  run("Firefox: our manifest + our add-on ID", [ff, "password-fill@nuvori.santoshkanumuri.com"], true),
  run("Firefox: our manifest + another add-on", [ff, "evil@example.com"], false),
  run("Firefox: another manifest path", [path.join(root, "other.json"), "password-fill@nuvori.santoshkanumuri.com"], false),
  run("Firefox: no add-on ID", [ff], false),
  run("Chrome: registered origin", ["chrome-extension://kapellkbongejlglcengbmjnpblemmjm/", "--parent-window=0"], true),
  run("Chrome: unregistered origin", ["chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/"], false),
];
fs.rmSync(root, { recursive: true, force: true });
process.exit(results.every(Boolean) ? 0 : 1);
