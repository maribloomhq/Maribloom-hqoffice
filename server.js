/* Maribloom HQ · virtual office on Railway.
   No packages needed. If APP_PASSWORD is set in Railway Variables, the office asks for it (recommended).
   Without APP_PASSWORD the office is open to anyone with the link. */
const http = require("http"), fs = require("fs"), path = require("path"), crypto = require("crypto");
const PORT = process.env.PORT || 8080;
const APP_PASSWORD = process.env.APP_PASSWORD || "";
const SECRET = process.env.SESSION_SECRET || crypto.createHash("sha256").update("mb-hq:" + APP_PASSWORD).digest("hex");
const DAYS = 30;
const FILES = { "/icon.svg": "image/svg+xml", "/icon-32.png": "image/png", "/icon-180.png": "image/png", "/assistant.png": "image/png" };
const read = (f) => fs.readFileSync(path.join(__dirname, f));
const sign = (v) => crypto.createHmac("sha256", SECRET).update(v).digest("hex");
const makeToken = () => { const exp = String(Date.now() + DAYS * 864e5); return `${exp}.${sign(exp)}`; };
const validToken = (t) => { if (!t) return false; const [exp, sig] = t.split("."); if (!exp || !sig || Number(exp) < Date.now()) return false;
  const a = Buffer.from(sig), b = Buffer.from(sign(exp)); return a.length === b.length && crypto.timingSafeEqual(a, b); };
const cookie = (req) => { const m = (req.headers.cookie || "").match(/(?:^|;\s*)hq_session=([^;]+)/); return m ? decodeURIComponent(m[1]) : ""; };
const authed = (req) => !APP_PASSWORD || validToken(cookie(req));
const samePass = (p) => { const a = crypto.createHash("sha256").update(String(p)).digest(), b = crypto.createHash("sha256").update(APP_PASSWORD).digest(); return crypto.timingSafeEqual(a, b); };
const tries = new Map();
const limited = (ip) => { const now = Date.now(); const t = (tries.get(ip) || []).filter((x) => now - x < 15 * 60e3); tries.set(ip, t); return t.length >= 8; };
const send = (res, code, type, body, extra = {}) => { res.writeHead(code, { "Content-Type": type, "X-Content-Type-Options": "nosniff", "Referrer-Policy": "same-origin", "X-Frame-Options": "SAMEORIGIN", ...extra }); res.end(body); };
const json = (res, code, obj, extra) => send(res, code, "application/json", JSON.stringify(obj), extra);
const setCookie = (req, val, maxAge) => `hq_session=${val}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${req.headers["x-forwarded-proto"] === "https" ? "; Secure" : ""}`;

http.createServer((req, res) => {
  const url = new URL(req.url, "http://x"); const p = url.pathname;
  const ip = (req.headers["x-forwarded-for"] || "").split(",")[0].trim() || req.socket.remoteAddress || "x";
  if (p === "/health") return json(res, 200, { ok: true, login: !!APP_PASSWORD });
  if (FILES[p] && req.method === "GET") return send(res, 200, FILES[p], read(p.slice(1)), { "Cache-Control": "public, max-age=604800" });
  if (p === "/favicon.ico") return send(res, 301, "text/plain", "", { Location: "/icon-32.png" });
  if (p === "/login" && req.method === "GET") return authed(req) ? send(res, 302, "text/plain", "", { Location: "/" }) : send(res, 200, "text/html; charset=utf-8", read("login.html"), { "Cache-Control": "no-store" });
  if (p === "/api/login" && req.method === "POST") {
    let body = ""; req.on("data", (c) => { body += c; if (body.length > 4096) req.destroy(); });
    req.on("end", () => {
      if (limited(ip)) return json(res, 429, { error: "Too many tries. Wait 15 minutes, then try again." });
      if (!APP_PASSWORD) return json(res, 200, { ok: true });
      let pw = ""; try { pw = JSON.parse(body).password || ""; } catch {}
      if (!samePass(pw)) { tries.get(ip).push(Date.now()); return json(res, 401, { error: "That password isn't right." }); }
      tries.delete(ip); json(res, 200, { ok: true }, { "Set-Cookie": setCookie(req, makeToken(), DAYS * 86400) });
    }); return;
  }
  if (p === "/api/logout" && req.method === "POST") return json(res, 200, { ok: true }, { "Set-Cookie": setCookie(req, "", 0) });
  if (!authed(req)) return send(res, 302, "text/plain", "", { Location: "/login" });
  if ((p === "/" || p === "/index.html") && req.method === "GET") return send(res, 200, "text/html; charset=utf-8", read("index.html"), { "Cache-Control": "no-cache" });
  send(res, 404, "text/plain", "Not found");
}).listen(PORT, () => console.log(`Maribloom HQ running on port ${PORT} (login ${APP_PASSWORD ? "ON" : "OFF — add APP_PASSWORD to make it private"})`));
