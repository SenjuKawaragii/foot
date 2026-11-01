import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

/*
  Serveur multijoueur de Foot Boosters (Netlify Functions + Netlify Blobs).
  - comptes : pseudo + mot de passe
  - documents partagés : chacun écrit seulement dans son espace, tout le monde lit
  - "poll" : le navigateur demande les changements (attente longue ~7 s) -> mises à jour presque instantanées
*/

const SELF = new Set(["pub", "pcol", "fr", "mk", "out", "rp", "cards", "clubs"]);
const SEG = /^[A-Za-z0-9_\-.~:@+]{1,200}$/;
const MAXDOC = 256 * 1024;
const J = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { "content-type": "application/json", "cache-control": "no-store" } });
const bad = (code, message, s = 400) => J({ code, message }, s);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const store = () => getStore({ name: "foot", consistency: "strong" });

function okPath(p) {
  if (typeof p !== "string") return false;
  const s = p.split("/");
  return s.length >= 1 && s.length <= 12 && s.every((x) => SEG.test(x) && x !== "." && x !== "..");
}
function canWrite(uid, p) {
  const s = p.split("/");
  if (s[0] === "data" && s[1] === "users") return s[2] === uid;
  if (SELF.has(s[0])) return s[1] === uid;
  return false;
}
function canRead(uid, p) {
  const s = p.split("/");
  if (s[0] === "data" && s[1] === "users") return s[2] === uid;
  return SELF.has(s[0]);
}
function merge(a, b) {
  for (const k of Object.keys(b)) {
    if (b[k] && typeof b[k] === "object" && !Array.isArray(b[k]) && a[k] && typeof a[k] === "object" && !Array.isArray(a[k])) merge(a[k], b[k]);
    else a[k] = JSON.parse(JSON.stringify(b[k]));
  }
  return a;
}
const hash = (pass, salt) => crypto.scryptSync(pass, salt, 32).toString("hex");
const newToken = () => crypto.randomBytes(24).toString("hex");
const bump = (s) => s.set("ver", Date.now() + "-" + crypto.randomBytes(3).toString("hex"));

async function session(s, uid, name) {
  const tok = newToken();
  await s.setJSON("tok/" + tok, { uid, t: Date.now() });
  const adm = await s.get("admin", { type: "text" });
  return { tok, uid, name, owner: adm === uid };
}
async function reg(s, b) {
  const name = String(b.name || "").trim();
  const pass = String(b.pass || "");
  if (!/^[\p{L}\p{N}_\- ]{2,20}$/u.test(name)) return bad("bad_name", "Pseudo : 2 à 20 caractères (lettres, chiffres, espace, - ou _).");
  if (pass.length < 4 || pass.length > 64) return bad("bad_pass", "Mot de passe : 4 caractères minimum.");
  const key = "acc/" + name.toLowerCase();
  if ((await s.get(key, { type: "json" })) !== null) return bad("exists", "Ce pseudo est déjà pris.", 409);
  const uid = "u" + crypto.randomBytes(8).toString("hex");
  const salt = crypto.randomBytes(16).toString("hex");
  await s.setJSON(key, { id: uid, name, salt, hash: hash(pass, salt), t: Date.now() });
  await s.setJSON("uid/" + uid, { name });
  if ((await s.get("admin", { type: "text" })) === null) await s.set("admin", uid);
  return J(await session(s, uid, name));
}
async function login(s, b) {
  const name = String(b.name || "").trim();
  const acc = await s.get("acc/" + name.toLowerCase(), { type: "json" });
  if (!acc) return bad("bad", "Pseudo ou mot de passe incorrect.", 401);
  const h = hash(String(b.pass || ""), acc.salt);
  if (!crypto.timingSafeEqual(Buffer.from(h), Buffer.from(acc.hash))) return bad("bad", "Pseudo ou mot de passe incorrect.", 401);
  return J(await session(s, acc.id, acc.name));
}
async function poll(s, uid, b) {
  const subs = b.subs && typeof b.subs === "object" ? b.subs : {};
  const cols = Object.keys(subs).filter((c) => okPath(c) && canRead(uid, c + "/x")).slice(0, 80);
  const t0 = Date.now();
  let cur;
  for (;;) {
    cur = (await s.get("ver", { type: "text" })) || "0";
    const needInit = cols.some((c) => subs[c] === null);
    if (b.force || needInit || cur !== b.ver) break;
    if (Date.now() - t0 > 7000) return J({ same: true, ver: cur });
    await sleep(500);
  }
  const out = {};
  let budget = 3000000, more = false;
  for (const c of cols) {
    const have = subs[c] && typeof subs[c] === "object" ? subs[c] : {};
    const prefix = "doc/" + c + "/";
    const { blobs } = await s.list({ prefix });
    const now = {};
    for (const bl of blobs) {
      const id = bl.key.slice(prefix.length);
      if (id && !id.includes("/")) now[id] = bl.etag;
    }
    const docs = {}, etags = {}, del = [];
    for (const id of Object.keys(have)) if (!(id in now)) del.push(id);
    for (const id of Object.keys(now)) {
      if (have[id] === now[id]) continue;
      if (budget <= 0) { more = true; continue; }
      const d = await s.get(prefix + id, { type: "json" });
      if (d === null) continue;
      budget -= JSON.stringify(d).length;
      docs[id] = d;
      etags[id] = now[id];
    }
    if (Object.keys(docs).length || del.length || subs[c] === null) out[c] = { docs, etags, del };
  }
  return J({ ver: more ? b.ver : cur, cols: out, more });
}

export default async (req) => {
  const url = new URL(req.url);
  if (url.searchParams.get("ping")) return J({ ok: true });
  if (req.method !== "POST") return bad("method", "POST attendu", 405);
  let b;
  try { b = await req.json(); } catch { return bad("invalid_argument", "JSON invalide"); }
  const s = store();
  const op = b.op;
  try {
    if (op === "reg") return await reg(s, b);
    if (op === "login") return await login(s, b);
    const t = await s.get("tok/" + String(req.headers.get("x-token") || "").replace(/[^a-f0-9]/g, ""), { type: "json" });
    const uid = t && t.uid;
    if (!uid) return bad("unauthorized", "Connecte-toi", 401);
    if (op === "me") {
      const u = await s.get("uid/" + uid, { type: "json" });
      return J({ uid, name: (u && u.name) || "", owner: (await s.get("admin", { type: "text" })) === uid });
    }
    if (op === "names") {
      const ids = Array.isArray(b.ids) ? b.ids.slice(0, 100) : [];
      const names = {};
      for (const id of ids) if (/^u[a-f0-9]{16}$/.test(id)) { const u = await s.get("uid/" + id, { type: "json" }); if (u) names[id] = u.name; }
      return J({ names });
    }
    if (op === "poll") return await poll(s, uid, b);
    const path = b.path;
    if (!okPath(path)) return bad("invalid_argument", "Chemin invalide");
    if (op === "get") {
      if (!canRead(uid, path)) return bad("permission_denied", "Lecture refusée", 403);
      return J({ data: await s.get("doc/" + path, { type: "json" }) });
    }
    if (op === "set" || op === "update" || op === "del") {
      if (!canWrite(uid, path)) return bad("invalid_argument", "Écriture refusée ici", 403);
      if (op === "del") { await s.delete("doc/" + path); await bump(s); return J({ ok: true }); }
      const d = b.data;
      if (!d || typeof d !== "object" || Array.isArray(d)) return bad("invalid_argument", "Document invalide");
      let data = d;
      if (op === "update") {
        const old = await s.get("doc/" + path, { type: "json" });
        if (old === null) return bad("invalid_argument", "Document absent");
        data = merge(old, d);
      }
      if (JSON.stringify(data).length > MAXDOC) return bad("invalid_argument", "Document trop gros (256 Ko max)");
      await s.setJSON("doc/" + path, data);
      await bump(s);
      return J({ ok: true, data });
    }
    return bad("invalid_argument", "Opération inconnue");
  } catch (e) {
    return bad("server", String((e && e.message) || e), 500);
  }
};
