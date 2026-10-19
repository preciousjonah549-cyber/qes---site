import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

export const config = { path: "/api/*" };

const STATUSES = ["Awaiting payment", "Paid", "Confirmed", "Delivered"];
const CORS = {
  "access-control-allow-origin": "*",
  "access-control-allow-headers": "x-secret-key, authorization, content-type",
  "access-control-allow-methods": "GET, OPTIONS",
};
const json = (d, s = 200, h = {}) =>
  new Response(JSON.stringify(d), {
    status: s,
    headers: { "content-type": "application/json", "cache-control": "no-store", ...h },
  });
const safeEq = (a, b) => {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};
const hashPw = (pw, salt) => crypto.pbkdf2Sync(pw, salt, 120000, 32, "sha256").toString("hex");
const makeToken = (secret) => {
  const exp = String(Date.now() + 7 * 24 * 3600 * 1000);
  return exp + "." + crypto.createHmac("sha256", secret).update(exp).digest("hex");
};
const checkToken = (auth, token) => {
  if (!auth || !token) return false;
  const [exp, sig] = String(token).split(".");
  if (!exp || !sig || Number(exp) < Date.now()) return false;
  return safeEq(sig, crypto.createHmac("sha256", auth.secret).update(exp).digest("hex"));
};

const PAIDISH = ["Paid", "Confirmed", "Delivered"];
const getLink = async (s) => (await s.get("link", { type: "json" })) || { url: "", key: "", when: "paid" };
const publicOrder = (o) => ({ order_id: o.order_id, customer_name: o.customer_name, phone: o.phone, items: o.items, total: o.total, status: o.status, created_at: o.created_at });
// Push one order to the sales manager (PearlVerse tracker) inbox.
async function forward(o, link) {
  const u = link.url + (link.url.includes("?") ? "&" : "?") + "key=" + encodeURIComponent(link.key);
  const r = await fetch(u, {
    method: "POST",
    headers: { "content-type": "application/json" },
    signal: AbortSignal.timeout(8000),
    body: JSON.stringify({
      id: o.order_id, date: o.created_at, customerName: o.customer_name, customerPhone: o.phone,
      items: o.items.map((i) => ({ name: i.name, qty: i.qty, price: i.price })),
      total: o.total, paid: PAIDISH.includes(o.status), paymentMethod: "Website (bank transfer)",
    }),
  });
  if (!r.ok) throw new Error("Sales manager replied " + r.status);
}
async function tryForward(o, link) {
  if (o.forwarded || !link.url || !link.key) return;
  if (link.when !== "placed" && !PAIDISH.includes(o.status)) return;
  try { await forward(o, link); o.forwarded = true; delete o.fwdError; }
  catch (e) { o.fwdError = String(e.message || e).slice(0, 120); }
}

export default async (req) => {
  const url = new URL(req.url);
  const path = url.pathname.replace(/^\/api\/?/, "").replace(/\/$/, "");
  const method = req.method;
  if (method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
  if (path === "ping") return json({ ok: true, time: new Date().toISOString() });

  try {
    const s = getStore({ name: "qes", consistency: "strong" });
    const auth = await s.get("auth", { type: "json" });
    const bearer = (req.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");
    const isAdmin = checkToken(auth, bearer);
    const body = async () => { try { return await req.json(); } catch { return {}; } };

    // ---- Public site data ----
    if (path === "site" && method === "GET") {
      let data = await s.get("site", { type: "json" });
      if (data && !isAdmin && Array.isArray(data.items)) data = { ...data, items: data.items.filter((i) => i.visible) };
      return json({ configured: !!auth, data });
    }
    if (path === "site" && method === "PUT") {
      if (!isAdmin) return json({ error: "Please sign in again." }, 401);
      const { data } = await body();
      if (!data || !Array.isArray(data.items)) return json({ error: "Invalid data." }, 400);
      if (JSON.stringify(data).length > 8_000_000) return json({ error: "Too much data. Remove some photos." }, 413);
      await s.setJSON("site", data);
      return json({ ok: true });
    }

    // ---- Admin password ----
    if (path === "auth/setup" && method === "POST") {
      if (auth) return json({ error: "A password has already been set." }, 409);
      const { password } = await body();
      if (typeof password !== "string" || password.length < 8) return json({ error: "Use at least 8 characters." }, 400);
      const salt = crypto.randomBytes(16).toString("hex");
      const a = { salt, hash: hashPw(password, salt), secret: crypto.randomBytes(32).toString("hex") };
      await s.setJSON("auth", a);
      return json({ token: makeToken(a.secret) });
    }
    if (path === "auth/login" && method === "POST") {
      if (!auth) return json({ error: "No password has been set yet." }, 400);
      const t = (await s.get("throttle", { type: "json" })) || { n: 0, until: 0 };
      if (t.until > Date.now()) return json({ error: "Too many attempts. Wait a few minutes and try again." }, 429);
      const { password } = await body();
      if (typeof password === "string" && safeEq(hashPw(password, auth.salt), auth.hash)) {
        await s.setJSON("throttle", { n: 0, until: 0 });
        return json({ token: makeToken(auth.secret) });
      }
      const n = t.n + 1;
      await s.setJSON("throttle", n >= 5 ? { n: 0, until: Date.now() + 5 * 60 * 1000 } : { n, until: 0 });
      return json({ error: "Wrong password. Try again." }, 401);
    }
    if (path === "auth/change" && method === "POST") {
      if (!isAdmin) return json({ error: "Please sign in again." }, 401);
      const { current, password } = await body();
      if (typeof current !== "string" || !safeEq(hashPw(current, auth.salt), auth.hash)) return json({ error: "Current password is wrong." }, 401);
      if (typeof password !== "string" || password.length < 8) return json({ error: "Use at least 8 characters." }, 400);
      const salt = crypto.randomBytes(16).toString("hex");
      const a = { salt, hash: hashPw(password, salt), secret: crypto.randomBytes(32).toString("hex") };
      await s.setJSON("auth", a);
      return json({ token: makeToken(a.secret) });
    }

    // ---- Orders ----
    if (path === "orders" && method === "POST") {
      const site = await s.get("site", { type: "json" });
      if (!site || !Array.isArray(site.items)) return json({ error: "The shop is not ready yet. Please try again later." }, 503);
      const b = await body();
      const name = String(b.customer_name || "").trim().slice(0, 80);
      const phone = String(b.phone || "").trim().slice(0, 30);
      if (!name || phone.replace(/\D/g, "").length < 10) return json({ error: "Enter your name and a valid phone number." }, 400);
      const lines = Array.isArray(b.items) ? b.items.slice(0, 40) : [];
      const items = [];
      let total = 0;
      for (const l of lines) {
        const it = site.items.find((x) => x.id === l.id && x.visible);
        const q = Math.floor(Number(l.qty));
        if (!it || !(q >= 1 && q <= 99)) return json({ error: "Some items are no longer available. Refresh and try again." }, 400);
        items.push({ name: it.name, qty: q, price: it.price });
        total += it.price * q;
      }
      if (!items.length) return json({ error: "Your cart is empty." }, 400);
      const orders = (await s.get("orders", { type: "json" })) || [];
      let id;
      do { id = "QES-" + (1000 + crypto.randomInt(9000)); } while (orders.some((o) => o.order_id === id));
      const order = { order_id: id, customer_name: name, phone, items, total, status: STATUSES[0], created_at: new Date().toISOString() };
      await tryForward(order, await getLink(s));
      orders.unshift(order);
      await s.setJSON("orders", orders.slice(0, 5000));
      return json({ order: publicOrder(order) });
    }
    if (path === "track" && method === "GET") {
      const id = String(url.searchParams.get("id") || "").trim().toUpperCase();
      const o = ((await s.get("orders", { type: "json" })) || []).find((x) => x.order_id === id);
      if (!o) return json({ error: "Not found" }, 404);
      return json({ order: { order_id: o.order_id, status: o.status, items: o.items, total: o.total, created_at: o.created_at } });
    }
    if (path === "orders" && method === "GET") {
      const key = process.env.SECRET_KEY || "";
      const sent = req.headers.get("x-secret-key") || bearer;
      const keyOk = key && sent && safeEq(sent, key);
      if (!isAdmin && !keyOk) return json({ error: "Not allowed." }, 401, CORS);
      return json((await s.get("orders", { type: "json" })) || [], 200, CORS);
    }
    if (path === "orders/status" && method === "POST") {
      if (!isAdmin) return json({ error: "Please sign in again." }, 401);
      const { id, status } = await body();
      if (!STATUSES.includes(status)) return json({ error: "Invalid status." }, 400);
      const orders = (await s.get("orders", { type: "json" })) || [];
      const o = orders.find((x) => x.order_id === id);
      if (!o) return json({ error: "Order not found." }, 404);
      o.status = status;
      await tryForward(o, await getLink(s));
      await s.setJSON("orders", orders);
      return json({ ok: true, forwarded: !!o.forwarded, fwdError: o.fwdError || "" });
    }
    if (path === "link" && method === "GET") {
      if (!isAdmin) return json({ error: "Please sign in again." }, 401);
      const l = await getLink(s);
      return json({ url: l.url, when: l.when, hasKey: !!l.key });
    }
    if (path === "link" && method === "POST") {
      if (!isAdmin) return json({ error: "Please sign in again." }, 401);
      const b = await body();
      const url = String(b.url || "").trim();
      if (url && !/^https:\/\//i.test(url)) return json({ error: "Use the full address starting with https://" }, 400);
      const l = await getLink(s);
      l.url = url;
      if (typeof b.key === "string" && b.key.trim()) l.key = b.key.trim();
      l.when = b.when === "placed" ? "placed" : "paid";
      await s.setJSON("link", l);
      return json({ ok: true, hasKey: !!l.key });
    }
    if (path === "orders/forward" && method === "POST") {
      if (!isAdmin) return json({ error: "Please sign in again." }, 401);
      const link = await getLink(s);
      if (!link.url || !link.key) return json({ error: "Save the sales manager link first." }, 400);
      const orders = (await s.get("orders", { type: "json" })) || [];
      let sent = 0, failed = 0;
      for (const o of orders) {
        if (o.forwarded) continue;
        await tryForward(o, link);
        if (o.forwarded) sent++; else if (o.fwdError) failed++;
      }
      await s.setJSON("orders", orders);
      return json({ sent, failed });
    }
    return json({ error: "Not found" }, 404);
  } catch (e) {
    console.error(e);
    return json({ error: "Server error. Please try again." }, 500);
  }
};
