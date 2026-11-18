// Local HTTPS pages for cases public test sites do not cover. Two origins:
//   https://localhost:8443   the "site" (top pages)
//   https://127.0.0.1:8444   a different origin, used as a cross-site sign-in frame
// Every POST lands on /done, which shows what arrived (so a capture after navigation can be checked).
import https from "node:https";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const tls = { key: fs.readFileSync(path.join(here, "..", ".state", "key.pem")), cert: fs.readFileSync(path.join(here, "..", ".state", "cert.pem")) };
const page = (title, body) => `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>${title}</title>
<style>body{font:16px system-ui;margin:40px}label{display:block;margin:10px 0 4px}input,select{font:inherit;padding:6px;width:280px}button{margin-top:14px;font:inherit;padding:6px 14px}</style></head><body><h1>${title}</h1>${body}</body></html>`;

const PAGES = {
  // A real sign-in next to two honeypots that must never receive a value.
  "/honeypot": page("Honeypot login", `<form method="post" action="/done">
    <input name="email_confirm" autocomplete="off" style="position:absolute;left:-9999px" tabindex="-1">
    <label>Email <input name="email" type="email" autocomplete="username"></label>
    <div style="opacity:0;height:0;overflow:hidden"><input name="user_hp" type="text"><input name="pass_hp" type="password"></div>
    <label>Password <input name="password" type="password" autocomplete="current-password"></label>
    <button>Sign in</button></form>`),
  // A sign-in frame from another origin inside this page.
  "/frame-host": page("Frame host", `<p>The sign-in box below comes from https://127.0.0.1:8444.</p>
    <iframe src="https://127.0.0.1:8444/frame-login" width="420" height="300" style="border:1px solid #888"></iframe>`),
  // Change password for a site that has two saved accounts.
  "/change": page("Change password", `<form method="post" action="/done">
    <label>Username <input name="username" autocomplete="username" value="bob"></label>
    <label>Current password <input name="current" type="password" autocomplete="current-password"></label>
    <label>New password <input name="new1" type="password" autocomplete="new-password"></label>
    <label>Confirm new password <input name="new2" type="password" autocomplete="new-password"></label>
    <button>Change</button></form>`),
  // Sign-in with no form element and a JS button that "navigates" via history (SPA).
  "/spa": page("SPA sign-in", `<div id="app"><label>Email <input id="e" type="email" autocomplete="username"></label>
    <label>Password <input id="p" type="password" autocomplete="current-password"></label>
    <div role="button" tabindex="0" id="go" style="display:inline-block;margin-top:14px;padding:6px 14px;border:1px solid #333;cursor:pointer">Sign in</div></div>
    <script>document.getElementById("go").onclick=()=>{history.pushState({}, "", "/spa/home");document.getElementById("app").innerHTML="<p>Welcome</p>";};</script>`),
  // Password-only step (account chosen earlier), and a numeric PIN that must never be captured.
  "/password-only": page("Enter your password", `<form method="post" action="/done"><p>Signing in as alice@example.com</p>
    <label>Password <input name="password" type="password" autocomplete="current-password"></label><button>Continue</button></form>`),
  "/pin": page("Enter your PIN", `<form method="post" action="/done"><label>PIN <input name="pin" type="password" inputmode="numeric" maxlength="4"></label><button>Unlock</button></form>`),
  // Checkout with split card boxes and month/year selects, and a separate address block.
  "/checkout": page("Checkout", `<form method="post" action="/done">
    <fieldset><legend>Card</legend>
    <label>Name on card <input name="ccname" autocomplete="cc-name"></label>
    <label>Card number</label><input name="cc1" maxlength="4" style="width:60px"> <input name="cc2" maxlength="4" style="width:60px"> <input name="cc3" maxlength="4" style="width:60px"> <input name="cc4" maxlength="4" style="width:60px">
    <label>Expiry</label><select name="expm" autocomplete="cc-exp-month"><option value="">MM</option>${Array.from({ length: 12 }, (_, i) => `<option>${String(i + 1).padStart(2, "0")}</option>`).join("")}</select>
    <select name="expy" autocomplete="cc-exp-year"><option value="">YYYY</option>${Array.from({ length: 10 }, (_, i) => `<option>${2025 + i}</option>`).join("")}</select>
    <label>Security code <input name="cvc" autocomplete="cc-csc" maxlength="4" style="width:80px"></label></fieldset>
    <fieldset><legend>Shipping</legend>
    <label>First name <input name="fn" autocomplete="given-name"></label><label>Last name <input name="ln" autocomplete="family-name"></label>
    <label>Street <input name="a1" autocomplete="address-line1"></label><label>City <input name="city" autocomplete="address-level2"></label>
    <label>State <input name="st" autocomplete="address-level1"></label><label>ZIP <input name="zip" autocomplete="postal-code"></label>
    <label>Phone <input name="tel" type="tel" autocomplete="tel"></label></fieldset>
    <button>Pay</button></form>`),
  // Six single-digit code boxes.
  "/otp-boxes": page("Two-step verification", `<form method="post" action="/done"><p>Enter the 6-digit code from your authenticator app.</p>
    ${Array.from({ length: 6 }, (_, i) => `<input name="d${i}" maxlength="1" inputmode="numeric" style="width:32px;text-align:center">`).join(" ")}<br><button>Verify</button></form>`),
  "/newsletter": page("Newsletter", `<form method="post" action="/done"><label>Your email <input name="email" type="email"></label><button>Subscribe</button></form>`),
};
const FRAME_PAGES = {
  "/frame-login": page("Frame sign-in", `<form method="post" action="/done"><label>Email <input name="email" type="email" autocomplete="username"></label>
    <label>Password <input name="password" type="password" autocomplete="current-password"></label><button>Sign in</button></form>`),
};

function handler(pages) {
  return (req, res) => {
    const url = new URL(req.url, "https://x");
    if (req.method === "POST") {
      let body = "";
      req.on("data", (c) => { body += c; });
      req.on("end", () => {
        const fields = Object.fromEntries(new URLSearchParams(body));
        res.writeHead(200, { "content-type": "text/html" });
        res.end(page("Done", `<p>Signed in.</p><pre id="received">${JSON.stringify(Object.keys(fields))}</pre>`));
      });
      return;
    }
    const html = pages[url.pathname] || (url.pathname.startsWith("/spa/") ? pages["/spa"] : null);
    res.writeHead(html ? 200 : 404, { "content-type": "text/html" });
    res.end(html || "not found");
  };
}

export function start() {
  const a = https.createServer(tls, handler(PAGES)).listen(8443);
  const b = https.createServer(tls, handler(FRAME_PAGES)).listen(8444);
  return () => { a.close(); b.close(); };
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) { start(); console.log("fixtures on https://localhost:8443 and https://127.0.0.1:8444"); }
