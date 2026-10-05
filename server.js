// Agenda Rinnovi Patente — Agenzia MC Servizi
// Server Node.js senza dipendenze: login con utente e password, archivio su file JSON.
"use strict";
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = Number(process.env.PORT) || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const DB_FILE = path.join(DATA_DIR, "db.json");
const PUBLIC_DIR = path.join(__dirname, "public");
const SESSION_DAYS = 30;
const COLLECTIONS = ["sessioni", "appuntamenti", "scadenze"];
const RUOLI = ["admin", "operatore", "consultazione"];

/* ---------------- archivio ---------------- */
fs.mkdirSync(DATA_DIR, { recursive: true });
let db;
function emptyDb() {
  return { versione: 1, utenti: [], token: {}, sessioni: {}, appuntamenti: {}, scadenze: {} };
}
function loadDb() {
  try {
    db = JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
    for (const k of Object.keys(emptyDb())) if (db[k] == null) db[k] = emptyDb()[k];
  } catch (e) {
    if (e.code !== "ENOENT") {
      console.error("Archivio illeggibile:", e.message);
      const bak = DB_FILE + ".illeggibile-" + Date.now();
      try { fs.copyFileSync(DB_FILE, bak); console.error("Copia salvata in", bak); } catch (_) {}
    }
    db = emptyDb();
  }
}
let saveTimer = null;
function saveDb() {
  // scrittura atomica: file temporaneo e poi rinomina
  const tmp = DB_FILE + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(db));
  fs.renameSync(tmp, DB_FILE);
}
function touch() { db.versione++; saveDb(); }
loadDb();

/* backup giornaliero (ultimi 14) */
function backup() {
  try {
    const dir = path.join(DATA_DIR, "backup");
    fs.mkdirSync(dir, { recursive: true });
    const f = path.join(dir, "db-" + new Date().toISOString().slice(0, 10) + ".json");
    if (!fs.existsSync(f) && fs.existsSync(DB_FILE)) fs.copyFileSync(DB_FILE, f);
    const all = fs.readdirSync(dir).filter(n => n.startsWith("db-")).sort();
    while (all.length > 14) fs.unlinkSync(path.join(dir, all.shift()));
  } catch (e) { console.error("Backup non riuscito:", e.message); }
}
backup();
setInterval(backup, 6 * 3600 * 1000).unref();

/* ---------------- password e sessioni ---------------- */
function hashPassword(pw, salt) {
  salt = salt || crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(pw, salt, 64).toString("hex");
  return { salt, hash };
}
function checkPassword(user, pw) {
  const h = crypto.scryptSync(pw, user.salt, 64);
  const ref = Buffer.from(user.hash, "hex");
  return h.length === ref.length && crypto.timingSafeEqual(h, ref);
}
const sha = s => crypto.createHash("sha256").update(s).digest("hex");
function newId(p) { return p + Date.now().toString(36) + crypto.randomBytes(3).toString("hex"); }
function pwOk(pw) { return typeof pw === "string" && pw.length >= 8 && pw.length <= 200; }

// primo avvio: crea l'amministratore
if (!db.utenti.length) {
  const username = (process.env.ADMIN_USERNAME || "admin").trim().toLowerCase();
  let pw = process.env.ADMIN_PASSWORD;
  const generated = !pw;
  if (generated) pw = crypto.randomBytes(9).toString("base64url");
  db.utenti.push(Object.assign({ id: newId("u"), username, nome: "Amministratore", ruolo: "admin", attivo: true, cambiaPassword: true, creato: new Date().toISOString() }, hashPassword(pw)));
  saveDb();
  console.log("==============================================");
  console.log(" Primo avvio: creato l'utente amministratore");
  console.log(" Utente:   " + username);
  console.log(" Password: " + (generated ? pw : "(quella impostata in ADMIN_PASSWORD)"));
  console.log(" Al primo accesso verrà chiesto di cambiarla.");
  console.log("==============================================");
}

function pruneTokens() {
  const now = Date.now();
  for (const [k, t] of Object.entries(db.token)) if (t.scade < now) delete db.token[k];
}

/* tentativi di accesso falliti: max 10 ogni 15 minuti per indirizzo */
const fails = new Map();
function tooMany(ip) {
  const f = fails.get(ip);
  if (!f) return false;
  if (Date.now() - f.da > 15 * 60 * 1000) { fails.delete(ip); return false; }
  return f.n >= 10;
}
function addFail(ip) {
  const f = fails.get(ip);
  if (!f || Date.now() - f.da > 15 * 60 * 1000) fails.set(ip, { n: 1, da: Date.now() });
  else f.n++;
}

/* ---------------- http ---------------- */
function parseCookies(req) {
  const out = {};
  (req.headers.cookie || "").split(";").forEach(p => {
    const i = p.indexOf("=");
    if (i > 0) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}
function isHttps(req) { return req.headers["x-forwarded-proto"] === "https"; }
function send(res, code, obj, headers) {
  const body = obj === undefined ? "" : JSON.stringify(obj);
  res.writeHead(code, Object.assign({ "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" }, headers || {}));
  res.end(body);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on("data", c => { size += c.length; if (size > 200 * 1024) { reject(Object.assign(new Error("troppo grande"), { status: 413 })); req.destroy(); } else chunks.push(c); });
    req.on("end", () => {
      if (!chunks.length) return resolve({});
      try {
        const v = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        if (!v || typeof v !== "object" || Array.isArray(v)) throw new Error();
        resolve(v);
      } catch (e) { reject(Object.assign(new Error("Dati non validi"), { status: 400 })); }
    });
    req.on("error", reject);
  });
}
function currentUser(req) {
  const tok = parseCookies(req).sid;
  if (!tok) return null;
  const t = db.token[sha(tok)];
  if (!t || t.scade < Date.now()) return null;
  const u = db.utenti.find(x => x.id === t.utente);
  if (!u || !u.attivo) return null;
  return u;
}
const pubUser = u => ({ id: u.id, username: u.username, nome: u.nome, ruolo: u.ruolo, attivo: u.attivo, cambiaPassword: !!u.cambiaPassword, creato: u.creato, ultimoAccesso: u.ultimoAccesso || null });
const STATIC = { "/": "index.html", "/index.html": "index.html", "/favicon.svg": "favicon.svg" };
const TYPES = { ".html": "text/html; charset=utf-8", ".svg": "image/svg+xml" };
const SEC_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "same-origin",
};

async function handle(req, res) {
  const url = new URL(req.url, "http://x");
  const p = url.pathname;
  const ip = (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim();

  if (req.method === "GET" && STATIC[p]) {
    const f = path.join(PUBLIC_DIR, STATIC[p]);
    return fs.readFile(f, (err, buf) => {
      if (err) { res.writeHead(404); return res.end(); }
      res.writeHead(200, Object.assign({ "Content-Type": TYPES[path.extname(f)], "Cache-Control": "no-cache" }, SEC_HEADERS));
      res.end(buf);
    });
  }
  if (p === "/health") return send(res, 200, { ok: true });
  if (!p.startsWith("/api/")) { res.writeHead(404, { "Content-Type": "text/plain" }); return res.end("Pagina non trovata"); }

  // protezione CSRF: le scritture devono arrivare dalla nostra pagina (header personalizzato)
  if (req.method !== "GET" && req.headers["x-requested-with"] !== "rinnovi") return send(res, 403, { errore: "Richiesta non consentita" });

  if (p === "/api/login" && req.method === "POST") {
    if (tooMany(ip)) return send(res, 429, { errore: "Troppi tentativi falliti. Riprova tra 15 minuti." });
    const b = await readBody(req);
    const username = String(b.username || "").trim().toLowerCase();
    const u = db.utenti.find(x => x.username === username);
    if (!u || !u.attivo || !checkPassword(u, String(b.password || ""))) {
      addFail(ip);
      return send(res, 401, { errore: "Utente o password non corretti." });
    }
    fails.delete(ip);
    pruneTokens();
    const tok = crypto.randomBytes(32).toString("hex");
    db.token[sha(tok)] = { utente: u.id, scade: Date.now() + SESSION_DAYS * 864e5 };
    u.ultimoAccesso = new Date().toISOString();
    saveDb();
    const cookie = `sid=${tok}; HttpOnly; Path=/; SameSite=Lax; Max-Age=${SESSION_DAYS * 86400}` + (isHttps(req) ? "; Secure" : "");
    return send(res, 200, { utente: pubUser(u) }, { "Set-Cookie": cookie });
  }
  if (p === "/api/logout" && req.method === "POST") {
    const tok = parseCookies(req).sid;
    if (tok) { delete db.token[sha(tok)]; saveDb(); }
    return send(res, 200, { ok: true }, { "Set-Cookie": "sid=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0" });
  }

  const me = currentUser(req);
  if (!me) return send(res, 401, { errore: "Accesso richiesto" });

  if (p === "/api/me" && req.method === "GET") return send(res, 200, { utente: pubUser(me) });
  if (p === "/api/me/password" && req.method === "POST") {
    const b = await readBody(req);
    if (!checkPassword(me, String(b.attuale || ""))) return send(res, 400, { errore: "La password attuale non è corretta." });
    if (!pwOk(b.nuova)) return send(res, 400, { errore: "La nuova password deve avere almeno 8 caratteri." });
    Object.assign(me, hashPassword(b.nuova));
    me.cambiaPassword = false;
    // chiude le altre sessioni di questo utente
    const cur = sha(parseCookies(req).sid);
    for (const [k, t] of Object.entries(db.token)) if (t.utente === me.id && k !== cur) delete db.token[k];
    saveDb();
    return send(res, 200, { utente: pubUser(me) });
  }
  if (me.cambiaPassword) return send(res, 403, { errore: "Cambia la password per continuare", cambiaPassword: true });

  /* ---- dati agenda ---- */
  if (p === "/api/dati" && req.method === "GET") {
    const v = Number(url.searchParams.get("v"));
    if (v && v === db.versione) return send(res, 200, { versione: db.versione, invariato: true });
    const out = { versione: db.versione };
    for (const c of COLLECTIONS) out[c] = Object.entries(db[c]).map(([id, r]) => Object.assign({}, r, { id }));
    const nomi = {}; db.utenti.forEach(u => nomi[u.id] = u.nome || u.username);
    out.nomi = nomi;
    return send(res, 200, out);
  }
  const m = p.match(/^\/api\/(sessioni|appuntamenti|scadenze)\/([A-Za-z0-9_-]{1,60})$/);
  if (m) {
    const [, col, id] = m;
    if (me.ruolo === "consultazione") return send(res, 403, { errore: "Il tuo utente può solo consultare l'agenda." });
    if (req.method === "PUT") {
      const b = await readBody(req);
      delete b.id;
      const prev = db[col][id];
      const now = new Date().toISOString();
      b.creatoDa = prev ? prev.creatoDa || null : me.id;
      b.creatoIl = prev ? prev.creatoIl || now : now;
      b.modificatoDa = me.id;
      b.modificatoIl = now;
      db[col][id] = b;
      touch();
      return send(res, 200, { versione: db.versione, record: Object.assign({}, b, { id }) });
    }
    if (req.method === "DELETE") {
      delete db[col][id];
      touch();
      return send(res, 200, { versione: db.versione });
    }
  }

  /* ---- gestione utenti (solo amministratore) ---- */
  if (p.startsWith("/api/utenti")) {
    if (me.ruolo !== "admin") return send(res, 403, { errore: "Solo l'amministratore gestisce gli utenti." });
    if (p === "/api/utenti" && req.method === "GET") return send(res, 200, { utenti: db.utenti.map(pubUser) });
    if (p === "/api/utenti" && req.method === "POST") {
      const b = await readBody(req);
      const username = String(b.username || "").trim().toLowerCase();
      if (!/^[a-z0-9._-]{3,30}$/.test(username)) return send(res, 400, { errore: "Nome utente: da 3 a 30 caratteri tra lettere, numeri, punto, trattino." });
      if (db.utenti.some(u => u.username === username)) return send(res, 400, { errore: "Questo nome utente esiste già." });
      if (!pwOk(b.password)) return send(res, 400, { errore: "La password deve avere almeno 8 caratteri." });
      const ruolo = RUOLI.includes(b.ruolo) ? b.ruolo : "operatore";
      const u = Object.assign({ id: newId("u"), username, nome: String(b.nome || "").trim().slice(0, 60) || username, ruolo, attivo: true, cambiaPassword: true, creato: new Date().toISOString() }, hashPassword(b.password));
      db.utenti.push(u); touch();
      return send(res, 200, { utente: pubUser(u) });
    }
    const mu = p.match(/^\/api\/utenti\/([A-Za-z0-9_-]+)$/);
    if (mu && req.method === "PUT") {
      const u = db.utenti.find(x => x.id === mu[1]);
      if (!u) return send(res, 404, { errore: "Utente non trovato" });
      const b = await readBody(req);
      const adminAttivi = db.utenti.filter(x => x.ruolo === "admin" && x.attivo);
      const toglieAdmin = (b.ruolo && b.ruolo !== "admin") || b.attivo === false;
      if (u.ruolo === "admin" && toglieAdmin && adminAttivi.length <= 1) return send(res, 400, { errore: "Deve restare almeno un amministratore attivo." });
      if (b.nome !== undefined) u.nome = String(b.nome).trim().slice(0, 60) || u.username;
      if (b.ruolo !== undefined && RUOLI.includes(b.ruolo)) u.ruolo = b.ruolo;
      if (b.attivo !== undefined) u.attivo = !!b.attivo;
      if (b.password) {
        if (!pwOk(b.password)) return send(res, 400, { errore: "La password deve avere almeno 8 caratteri." });
        Object.assign(u, hashPassword(b.password));
        u.cambiaPassword = u.id !== me.id;
      }
      if (b.password || u.attivo === false) for (const [k, t] of Object.entries(db.token)) if (t.utente === u.id && u.id !== me.id) delete db.token[k];
      touch();
      return send(res, 200, { utente: pubUser(u) });
    }
  }
  return send(res, 404, { errore: "Non trovato" });
}

const server = http.createServer((req, res) => {
  handle(req, res).catch(e => {
    if (!res.headersSent) send(res, e.status || 500, { errore: e.status ? e.message : "Errore del server" });
    if (!e.status) console.error(e);
  });
});
server.listen(PORT, () => console.log(`Agenda Rinnovi Patente in ascolto sulla porta ${PORT} (dati in ${DATA_DIR})`));
