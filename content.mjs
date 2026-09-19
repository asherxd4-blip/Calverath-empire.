import { getStore } from "@netlify/blobs";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

// PIN used until you change it from the site. Set EDIT_PIN in Netlify
// (Site configuration > Environment variables) to use a different starting PIN.
const DEFAULT_PIN = "618976";

const store = () => getStore({ name: "calverath", consistency: "strong" });
const digest = (pin, salt) => createHash("sha256").update(salt + "|" + pin).digest();
const reply = (obj, status = 200) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
const failures = new Map();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function pinOk(s, pin) {
  pin = String(pin ?? "");
  const rec = await s.get("pin", { type: "json" });
  if (rec) return timingSafeEqual(digest(pin, rec.salt), Buffer.from(rec.hash, "hex"));
  const expected = String(process.env.EDIT_PIN || DEFAULT_PIN);
  return timingSafeEqual(digest(pin, "env"), digest(expected, "env"));
}

export default async (req, context) => {
  const s = store();

  if (req.method === "GET") {
    const data = await s.get("site", { type: "json" });
    return reply(data || {});
  }
  if (req.method !== "POST") return reply({ error: "Method not allowed" }, 405);

  let body;
  try { body = await req.json(); } catch { return reply({ error: "Bad request" }, 400); }

  const ip = context?.ip || req.headers.get("x-nf-client-connection-ip") || "unknown";
  const f = failures.get(ip) || { n: 0, until: 0 };
  if (Date.now() < f.until) return reply({ error: "Too many attempts" }, 429);

  if (!(await pinOk(s, body.pin))) {
    f.n += 1;
    if (f.n >= 5) { f.until = Date.now() + 60_000; f.n = 0; }
    failures.set(ip, f);
    await sleep(700);
    return reply({ error: "Wrong PIN" }, 401);
  }
  failures.delete(ip);

  if (body.action === "auth") return reply({ ok: true });

  if (body.action === "save") {
    const d = body.data;
    if (!d || typeof d !== "object" || !Array.isArray(d.sections) || d.sections.length === 0)
      return reply({ error: "Invalid data" }, 400);
    delete d.pinHash;
    await s.setJSON("site", d);
    return reply({ ok: true });
  }

  if (body.action === "setpin") {
    const np = String(body.newPin ?? "");
    if (np.length < 4) return reply({ error: "PIN too short" }, 400);
    const salt = randomBytes(8).toString("hex");
    await s.setJSON("pin", { salt, hash: digest(np, salt).toString("hex") });
    return reply({ ok: true });
  }

  return reply({ error: "Unknown action" }, 400);
};

export const config = { path: "/api/content" };
