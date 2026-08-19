require("dotenv").config();

const path = require("node:path");
const crypto = require("node:crypto");
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { createClient } = require("@supabase/supabase-js");
const { z } = require("zod");

const app = express();
const port = Number(process.env.PORT || 3000);
const frontendOrigin = process.env.FRONTEND_ORIGIN;
const supabaseUrl = process.env.SUPABASE_URL;
const anonKey = process.env.SUPABASE_ANON_KEY;
const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const publicClient = supabaseUrl && anonKey ? createClient(supabaseUrl, anonKey) : null;
const adminClient = supabaseUrl && serviceRoleKey ? createClient(supabaseUrl, serviceRoleKey) : null;
const adminSessions = new Map();
const adminTtlMs = Math.max(5, Number(process.env.ADMIN_SESSION_TTL_MINUTES || 120)) * 60 * 1000;
const cookieName = "zedmoney_admin";

app.disable("x-powered-by");
app.use(helmet({ crossOriginResourcePolicy: { policy: "cross-origin" } }));
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || !frontendOrigin) return callback(null, !frontendOrigin);
    const allowed = frontendOrigin.split(",").map(v => v.trim()).filter(Boolean);
    callback(null, allowed.includes(origin));
  },
  credentials: true,
  methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "Idempotency-Key"]
}));
app.use(express.json({ limit: "32kb" }));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, limit: 300, standardHeaders: "draft-8", legacyHeaders: false }));

const frontendDir = process.env.FRONTEND_DIR ? path.resolve(process.env.FRONTEND_DIR) : __dirname;
const indexFile = process.env.INDEX_FILE ? path.resolve(process.env.INDEX_FILE) : path.join(frontendDir, "index.html");
const authFile = process.env.AUTH_FILE ? path.resolve(process.env.AUTH_FILE) : path.join(frontendDir, "auth.html");
app.use(express.static(frontendDir, { index: false }));
app.get("/", (_req, res) => res.sendFile(indexFile));
app.get("/index.html", (_req, res) => res.sendFile(indexFile));
app.get("/auth.html", (_req, res) => res.sendFile(authFile));

const ok = (res, data, status = 200) => res.status(status).json({ success: true, data });
const fail = (res, code, message, status = 400) => res.status(status).json({ success: false, error: { code, message } });
const safeId = z.string().uuid();
const money = z.coerce.number().finite().positive();

function bearer(req) {
  const value = req.get("authorization") || "";
  return value.startsWith("Bearer ") ? value.slice(7) : null;
}

function cookies(req) {
  return Object.fromEntries((req.get("cookie") || "").split(";").map(v => v.trim().split("=")).filter(v => v.length === 2));
}

function adminCookie(res, value, maxAge) {
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  res.setHeader("Set-Cookie", `${cookieName}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure}`);
}

function passwordMatches(password) {
  const stored = process.env.ADMIN_PASSWORD_HASH || "";
  if (!stored || !password) return false;
  if (stored.startsWith("sha256$")) {
    const actual = crypto.createHash("sha256").update(password).digest("hex");
    const expected = stored.slice(7);
    return actual.length === expected.length && crypto.timingSafeEqual(Buffer.from(actual), Buffer.from(expected));
  }
  if (stored.startsWith("scrypt$")) {
    const [, salt, digest] = stored.split("$");
    const actual = crypto.scryptSync(password, salt, 32).toString("hex");
    return actual.length === digest.length && crypto.timingSafeEqual(Buffer.from(actual), Buffer.from(digest));
  }
  return false;
}

async function requireAuth(req, res, next) {
  if (!publicClient) return fail(res, "WALLET_SERVICE_ERROR", "Wallet sign-in is temporarily unavailable. Please try again later.", 503);
  const token = bearer(req);
  if (!token) return fail(res, "UNAUTHENTICATED", "Please sign in to continue.", 401);
  const { data, error } = await publicClient.auth.getUser(token);
  if (error || !data.user) return fail(res, "UNAUTHENTICATED", "Your session has expired. Please sign in again.", 401);
  req.user = data.user;
  req.accessToken = token;
  next();
}

async function requireAdmin(req, res, next) {
  const token = cookies(req)[cookieName];
  const session = token && adminSessions.get(token);
  if (!session || session.expiresAt <= Date.now()) {
    if (token) adminSessions.delete(token);
    return fail(res, "ADMIN_UNAUTHENTICATED", "Sign in to the admin console.", 401);
  }
  session.expiresAt = Date.now() + adminTtlMs;
  req.user = { id: session.userId, email: "admin" };
  req.admin = { id: session.adminId || session.userId, active: true, role_id: session.roleId || null };
  next();
}

async function requireAdminPermission(req, permission, next) {
  await requireAdmin(req, res => fail(res, "FORBIDDEN", "Administrator authorization is required.", 403), async () => {});
}

async function hasAdminPermission(req, permission) {
  if (!req.admin) return false;
  if (!req.admin.role_id) return true;
  const { data, error } = await adminClient
    .from("admin_role_permissions")
    .select("permission:admin_permissions!inner(name)")
    .eq("role_id", req.admin.role_id)
    .eq("admin_permissions.name", permission);
  if (error) throw error;
  return Array.isArray(data) && data.length > 0;
}

async function requirePermission(req, res, permission) {
  if (!await hasAdminPermission(req, permission)) {
    fail(res, "FORBIDDEN", `Missing admin permission: ${permission}`, 403);
    return false;
  }
  return true;
}

async function audit(req, action, targetType, targetId, reason, note = null, metadata = {}) {
  const { error } = await db(req).from("audit_logs").insert({
    admin_user_id: req.admin.id, action, target_type: targetType, target_id: targetId,
    reason, note, ip_address: req.ip, user_agent: req.get("user-agent") || null, metadata
  });
  if (error) throw error;
}

function db(req) {
  if (!adminClient) throw Object.assign(new Error("Wallet service is temporarily unavailable"), { status: 503, code: "WALLET_SERVICE_ERROR" });
  return adminClient;
}

async function owned(req, table, id, column = "id") {
  const { data, error } = await db(req).from(table).select("*").eq(column, id).eq("user_id", req.user.id).maybeSingle();
  if (error) throw error;
  return data;
}

app.get("/api/health", (_req, res) => ok(res, { ok: true, service: "zedmoney-api" }));

app.post("/api/admin/login", async (req, res) => {
  const password = typeof req.body?.password === "string" ? req.body.password : "";
  if (!passwordMatches(password)) return fail(res, "INVALID_ADMIN_CREDENTIALS", "The admin password is incorrect.", 401);
  const userId = process.env.ADMIN_SYSTEM_USER_ID;
  if (!userId || !adminClient) return fail(res, "WALLET_SERVICE_ERROR", "The wallet service is temporarily unavailable.", 503);
  const { data: admin, error } = await adminClient.from("admin_users").select("id,active,role_id").eq("user_id", userId).maybeSingle();
  if (error) return fail(res, "WALLET_SERVICE_ERROR", "The wallet service is temporarily unavailable.", 503);
  if (!admin || admin.active === false) return fail(res, "FORBIDDEN", "Administrator authorization is required.", 403);
  const token = crypto.randomBytes(32).toString("base64url");
  adminSessions.set(token, { userId, adminId: admin.id, roleId: admin.role_id, expiresAt: Date.now() + adminTtlMs });
  adminCookie(res, token, Math.floor(adminTtlMs / 1000));
  return ok(res, { authenticated: true });
});

app.get("/api/admin/session", requireAdmin, (_req, res) => ok(res, { authenticated: true }));
app.post("/api/admin/logout", (req, res) => {
  const token = cookies(req)[cookieName];
  if (token) adminSessions.delete(token);
  adminCookie(res, "", 0);
  return ok(res, { authenticated: false });
});

app.get("/api/me", requireAuth, async (req, res, next) => {
  try {
    const client = db(req);
    const [{ data: profile }, { data: wallet }] = await Promise.all([
      client.from("profiles").select("*").eq("id", req.user.id).maybeSingle(),
      client.from("wallets").select("id,wallet_identifier,currency,status,available_balance,pending_balance,reserved_balance").eq("user_id", req.user.id).maybeSingle()
    ]);
    return ok(res, { user: { id: req.user.id, email: req.user.email }, profile, wallet });
  } catch (e) { next(e); }
});

app.get("/api/me/profile", requireAuth, async (req, res, next) => {
  try { const { data, error } = await db(req).from("profiles").select("*").eq("id", req.user.id).single(); if (error) throw error; ok(res, data); } catch (e) { next(e); }
});

app.patch("/api/me/profile", requireAuth, async (req, res, next) => {
  try {
    const schema = z.object({
      first_name: z.string().trim().min(1).max(80).optional(),
      last_name: z.string().trim().min(1).max(80).optional(),
      display_name: z.string().trim().max(120).optional(),
      username: z.string().trim().regex(/^[A-Za-z0-9_]{3,30}$/).optional(),
      phone: z.string().trim().max(40).optional(),
      country: z.string().trim().length(2).optional(),
      currency: z.string().trim().length(3).optional(),
      avatar_url: z.string().url().nullable().optional()
    }).strict();
    const { data, error } = await db(req).from("profiles").update(schema.parse(req.body)).eq("id", req.user.id).select().single();
    if (error) throw error; ok(res, data);
  } catch (e) { next(e); }
});

app.get("/api/wallet", requireAuth, async (req, res, next) => {
  try { const { data, error } = await db(req).from("wallets").select("*").eq("user_id", req.user.id).single(); if (error) throw error; ok(res, data); } catch (e) { next(e); }
});
app.get("/api/wallet/balance", requireAuth, async (req, res, next) => {
  try { const { data, error } = await db(req).from("wallets").select("available_balance,pending_balance,reserved_balance,currency,status").eq("user_id", req.user.id).single(); if (error) throw error; ok(res, data); } catch (e) { next(e); }
});

app.get("/api/transactions", requireAuth, async (req, res, next) => {
  try {
    const page = Math.max(1, Number(req.query.page || 1));
    const limit = Math.min(100, Math.max(1, Number(req.query.limit || 25)));
    let query = db(req).from("transactions").select("*", { count: "exact" }).eq("user_id", req.user.id).order("created_at", { ascending: false }).range((page - 1) * limit, page * limit - 1);
    for (const key of ["type", "status", "currency"]) if (req.query[key]) query = query.eq(key, req.query[key]);
    if (req.query.search) query = query.ilike("description", `%${String(req.query.search).slice(0, 80)}%`);
    const { data, count, error } = await query; if (error) throw error; ok(res, { items: data || [], page, limit, total: count || 0 });
  } catch (e) { next(e); }
});
app.get("/api/transactions/:id", requireAuth, async (req, res, next) => {
  try { safeId.parse(req.params.id); const data = await owned(req, "transactions", req.params.id); if (!data) return fail(res, "NOT_FOUND", "Transaction not found.", 404); ok(res, data); } catch (e) { next(e); }
});

app.post("/api/transfers", requireAuth, async (req, res, next) => {
  try {
    const schema = z.object({ recipient: z.string().trim().min(3).max(120), amount: money, currency: z.string().length(3).default("ZMW"), note: z.string().trim().max(240).optional() });
    const input = schema.parse(req.body);
    const key = req.get("Idempotency-Key"); if (!key) return fail(res, "IDEMPOTENCY_KEY_REQUIRED", "Idempotency-Key is required.", 400);
    const { data, error } = await db(req).rpc("create_internal_transfer", { p_sender_id: req.user.id, p_recipient: input.recipient, p_amount: input.amount, p_currency: input.currency, p_note: input.note || null, p_idempotency_key: key });
    if (error) throw error; ok(res, data, 201);
  } catch (e) { next(e); }
});

app.get("/api/transfers", requireAuth, async (req, res, next) => {
  try { const { data, error } = await db(req).from("transactions").select("*").eq("user_id", req.user.id).eq("type", "transfer").order("created_at", { ascending: false }); if (error) throw error; ok(res, data || []); } catch (e) { next(e); }
});

app.post("/api/deposits", requireAuth, async (req, res, next) => {
  try {
    const input = z.object({ amount: money, currency: z.string().length(3).default("ZMW"), method: z.enum(["mobile_money", "card", "ussd", "payment_link"]), description: z.string().max(240).optional() }).parse(req.body);
    const key = req.get("Idempotency-Key");
    if (!key) return fail(res, "IDEMPOTENCY_KEY_REQUIRED", "Idempotency-Key is required.", 400);
    const { data: existing } = await db(req).from("deposits").select("*").eq("user_id", req.user.id).eq("idempotency_key", key).maybeSingle();
    if (existing) return ok(res, existing);
    const { data, error } = await db(req).from("deposits").insert({ user_id: req.user.id, amount: input.amount, currency: input.currency, method: input.method, status: "pending", description: input.description || null, idempotency_key: key }).select().single();
    if (error) throw error; ok(res, data, 201);
  } catch (e) { next(e); }
});
app.get("/api/deposits", requireAuth, async (req, res, next) => { try { const { data, error } = await db(req).from("deposits").select("*").eq("user_id", req.user.id).order("created_at", { ascending: false }); if (error) throw error; ok(res, data || []); } catch (e) { next(e); } });
app.get("/api/deposits/:id", requireAuth, async (req, res, next) => { try { const data = await owned(req, "deposits", req.params.id); if (!data) return fail(res, "NOT_FOUND", "Deposit not found.", 404); ok(res, data); } catch (e) { next(e); } });

app.post("/api/withdrawals", requireAuth, async (req, res, next) => {
  try {
    const input = z.object({ amount: money, currency: z.string().length(3).default("ZMW"), method: z.enum(["mobile_money", "bank_account"]), destination: z.string().trim().min(3).max(160) }).parse(req.body);
    const key = req.get("Idempotency-Key"); if (!key) return fail(res, "IDEMPOTENCY_KEY_REQUIRED", "Idempotency-Key is required.", 400);
    const { data, error } = await db(req).rpc("initiate_withdrawal", { p_user_id: req.user.id, p_amount: input.amount, p_currency: input.currency, p_method: input.method, p_destination: input.destination, p_idempotency_key: key });
    if (error) throw error; ok(res, data, 201);
  } catch (e) { next(e); }
});
app.get("/api/withdrawals", requireAuth, async (req, res, next) => { try { const { data, error } = await db(req).from("withdrawals").select("*").eq("user_id", req.user.id).order("created_at", { ascending: false }); if (error) throw error; ok(res, data || []); } catch (e) { next(e); } });
app.get("/api/withdrawals/:id", requireAuth, async (req, res, next) => { try { const data = await owned(req, "withdrawals", req.params.id); if (!data) return fail(res, "NOT_FOUND", "Withdrawal not found.", 404); ok(res, data); } catch (e) { next(e); } });

app.get("/api/recipients", requireAuth, async (req, res, next) => { try { const { data, error } = await db(req).from("recipients").select("*").eq("user_id", req.user.id).order("favorite", { ascending: false }); if (error) throw error; ok(res, data || []); } catch (e) { next(e); } });
app.post("/api/recipients", requireAuth, async (req, res, next) => { try { const input = z.object({ label: z.string().trim().min(1).max(80), recipient_user_id: safeId.optional(), phone: z.string().max(40).optional(), favorite: z.boolean().default(false) }).parse(req.body); const { data, error } = await db(req).from("recipients").insert({ ...input, user_id: req.user.id }).select().single(); if (error) throw error; ok(res, data, 201); } catch (e) { next(e); } });
app.patch("/api/recipients/:id", requireAuth, async (req, res, next) => { try { const input = z.object({ label: z.string().trim().min(1).max(80).optional(), phone: z.string().max(40).optional(), favorite: z.boolean().optional() }).strict().parse(req.body); const { data, error } = await db(req).from("recipients").update(input).eq("id", req.params.id).eq("user_id", req.user.id).select().single(); if (error) throw error; ok(res, data); } catch (e) { next(e); } });
app.delete("/api/recipients/:id", requireAuth, async (req, res, next) => { try { const { error } = await db(req).from("recipients").delete().eq("id", req.params.id).eq("user_id", req.user.id); if (error) throw error; ok(res, { deleted: true }); } catch (e) { next(e); } });

app.get("/api/payment-links", requireAuth, async (req, res, next) => { try { const { data, error } = await db(req).from("payment_links").select("*").eq("owner_id", req.user.id).order("created_at", { ascending: false }); if (error) throw error; ok(res, data || []); } catch (e) { next(e); } });
app.post("/api/payment-links", requireAuth, async (req, res, next) => { try { const input = z.object({ amount: money, currency: z.string().length(3).default("ZMW"), description: z.string().trim().min(1).max(240), expires_at: z.string().datetime().optional() }).parse(req.body); const { data, error } = await db(req).from("payment_links").insert({ ...input, owner_id: req.user.id, status: "active" }).select().single(); if (error) throw error; ok(res, data, 201); } catch (e) { next(e); } });
app.get("/api/payment-links/:id", requireAuth, async (req, res, next) => { try { const { data, error } = await db(req).from("payment_links").select("*").eq("id", req.params.id).eq("owner_id", req.user.id).single(); if (error) throw error; ok(res, data); } catch (e) { next(e); } });
app.post("/api/payment-links/:id/disable", requireAuth, async (req, res, next) => { try { const { data, error } = await db(req).from("payment_links").update({ status: "disabled" }).eq("id", req.params.id).eq("owner_id", req.user.id).select().single(); if (error) throw error; ok(res, data); } catch (e) { next(e); } });

app.get("/api/requests", requireAuth, async (req, res, next) => { try { const { data, error } = await db(req).from("money_requests").select("*").or(`requester_id.eq.${req.user.id},payer_id.eq.${req.user.id}`).order("created_at", { ascending: false }); if (error) throw error; ok(res, data || []); } catch (e) { next(e); } });
app.post("/api/requests", requireAuth, async (req, res, next) => { try { const input = z.object({ payer_id: safeId, amount: money, currency: z.string().length(3).default("ZMW"), note: z.string().max(240).optional(), expires_at: z.string().datetime().optional() }).parse(req.body); const { data, error } = await db(req).from("money_requests").insert({ ...input, requester_id: req.user.id, status: "pending" }).select().single(); if (error) throw error; ok(res, data, 201); } catch (e) { next(e); } });
app.post("/api/requests/:id/accept", requireAuth, async (req,res,next)=>{try{safeId.parse(req.params.id);const {data,error}=await db(req).rpc("accept_money_request",{p_request_id:req.params.id,p_payer_id:req.user.id});if(error)throw error;ok(res,data);}catch(e){next(e);}});
for (const action of ["decline", "cancel"]) app.post(`/api/requests/:id/${action}`, requireAuth, async (req, res, next) => { try { safeId.parse(req.params.id); const patch = { status: action === "decline" ? "declined" : "cancelled" }; const { data, error } = await db(req).from("money_requests").update(patch).eq("id", req.params.id).or(`requester_id.eq.${req.user.id},payer_id.eq.${req.user.id}`).eq("status","pending").select().single(); if (error) throw error; ok(res, data); } catch (e) { next(e); } });

app.get("/api/notifications", requireAuth, async (req, res, next) => { try { const { data, error } = await db(req).from("notifications").select("*").eq("user_id", req.user.id).order("created_at", { ascending: false }); if (error) throw error; ok(res, data || []); } catch (e) { next(e); } });
app.post("/api/notifications/:id/read", requireAuth, async (req, res, next) => { try { const { data, error } = await db(req).from("notifications").update({ read_at: new Date().toISOString() }).eq("id", req.params.id).eq("user_id", req.user.id).select().single(); if (error) throw error; ok(res, data); } catch (e) { next(e); } });
app.post("/api/notifications/read-all", requireAuth, async (req, res, next) => { try { const { error } = await db(req).from("notifications").update({ read_at: new Date().toISOString() }).eq("user_id", req.user.id).is("read_at", null); if (error) throw error; ok(res, { updated: true }); } catch (e) { next(e); } });

app.get("/api/analytics", requireAuth, async (req, res, next) => { try { const { data, error } = await db(req).rpc("get_wallet_analytics", { p_user_id: req.user.id, p_from: req.query.from || null, p_to: req.query.to || null }); if (error) throw error; ok(res, data); } catch (e) { next(e); } });
app.get("/api/statements", requireAuth, async (req, res, next) => { try { const from = req.query.from || new Date(new Date().getFullYear(), new Date().getMonth(), 1).toISOString(); const to = req.query.to || new Date().toISOString(); const { data, error } = await db(req).from("transactions").select("*").eq("user_id", req.user.id).gte("created_at", from).lte("created_at", to).order("created_at", { ascending: false }); if (error) throw error; ok(res, { from, to, transactions: data || [] }); } catch (e) { next(e); } });
app.get("/api/security/events", requireAuth, async (req, res, next) => { try { const { data, error } = await db(req).from("security_events").select("id,type,description,device,created_at").eq("user_id", req.user.id).order("created_at", { ascending: false }); if (error) throw error; ok(res, data || []); } catch (e) { next(e); } });
app.get("/api/sessions", requireAuth, async (req, res, next) => { try { const { data, error } = await db(req).from("device_sessions").select("id,device_name,last_seen_at,revoked_at,created_at").eq("user_id", req.user.id).order("last_seen_at", { ascending: false }); if (error) throw error; ok(res, data || []); } catch (e) { next(e); } });

app.get("/api/admin/overview", requireAdmin, async (req, res, next) => {
  try {
    if (!await requirePermission(req, res, "overview.read")) return;
    const client = db(req);
    const [users, wallets, transactions, pending, suspended, frozen] = await Promise.all([
      client.from("profiles").select("id", { count: "exact", head: true }),
      client.from("wallets").select("id", { count: "exact", head: true }),
      client.from("transactions").select("id", { count: "exact", head: true }),
      client.from("transactions").select("id", { count: "exact", head: true }).in("status", ["pending", "processing"]),
      client.from("profiles").select("id", { count: "exact", head: true }).eq("status", "suspended"),
      client.from("wallets").select("id", { count: "exact", head: true }).eq("status", "frozen")
    ]);
    ok(res, { users: users.count || 0, wallets: wallets.count || 0, transactions: transactions.count || 0,
      pending_transactions: pending.count || 0, suspended_users: suspended.count || 0, frozen_wallets: frozen.count || 0 });
  } catch (e) { next(e); }
});

app.get("/api/admin/users", requireAdmin, async (req, res, next) => {
  try { if (!await requirePermission(req,res,"users.read")) return;
    const limit=Math.min(100,Math.max(1,Number(req.query.limit||50)));
    let q=db(req).from("profiles").select("*").order("created_at",{ascending:false}).limit(limit);
    if(req.query.status) q=q.eq("status",req.query.status);
    if(req.query.search){const term=String(req.query.search).slice(0,80);q=q.or(`first_name.ilike.%${term}%,last_name.ilike.%${term}%,phone.ilike.%${term}%,zedmoney_id.ilike.%${term}%`);}
    const {data,error}=await q;if(error)throw error;ok(res,data||[]);
  } catch(e){next(e);}
});

app.get("/api/admin/users/:id", requireAdmin, async (req,res,next)=>{
  try { if(!await requirePermission(req,res,"users.read"))return; safeId.parse(req.params.id);
    const [{data:profile,error:e1},{data:wallet,error:e2}]=await Promise.all([
      db(req).from("profiles").select("*").eq("id",req.params.id).maybeSingle(),
      db(req).from("wallets").select("*").eq("user_id",req.params.id).maybeSingle()
    ]); if(e1)throw e1;if(e2)throw e2;if(!profile)return fail(res,"NOT_FOUND","User not found.",404);ok(res,{profile,wallet});
  } catch(e){next(e);}
});

app.post("/api/admin/users/:id/suspend", requireAdmin, async (req,res,next)=>{
  try { if(!await requirePermission(req,res,"users.suspend"))return; safeId.parse(req.params.id);
    const reason=z.object({reason:z.string().trim().min(3).max(240)}).parse(req.body).reason;
    const {data,error}=await db(req).from("profiles").update({status:"suspended"}).eq("id",req.params.id).select().single();if(error)throw error;
    await audit(req,"SUSPEND_USER","user",req.params.id,reason);ok(res,data);
  } catch(e){next(e);}
});

app.post("/api/admin/users/:id/restore", requireAdmin, async (req,res,next)=>{
  try { if(!await requirePermission(req,res,"users.restore"))return; safeId.parse(req.params.id);
    const reason=z.object({reason:z.string().trim().min(3).max(240).default("Administrative review")}).parse(req.body||{}).reason;
    const {data,error}=await db(req).from("profiles").update({status:"active"}).eq("id",req.params.id).select().single();if(error)throw error;
    await audit(req,"RESTORE_USER","user",req.params.id,reason);ok(res,data);
  } catch(e){next(e);}
});

app.post("/api/admin/users/:id/restrict", requireAdmin, async (req,res,next)=>{
  try { if(!await requirePermission(req,res,"users.restrict"))return; safeId.parse(req.params.id);
    const input=z.object({restriction:z.enum(["cannot_send","cannot_receive","cannot_deposit","cannot_withdraw","cannot_create_payment_links","cannot_request_money"]),reason:z.string().trim().min(3).max(240)}).parse(req.body);
    const {data,error}=await db(req).from("user_restrictions").insert({user_id:req.params.id,restriction:input.restriction,reason:input.reason,active:true}).select().single();if(error)throw error;
    await db(req).from("profiles").update({status:"restricted"}).eq("id",req.params.id);await audit(req,"RESTRICT_USER","user",req.params.id,input.reason,null,{restriction:input.restriction});ok(res,data,201);
  } catch(e){next(e);}
});

app.get("/api/admin/wallets", requireAdmin, async (req,res,next)=>{try{if(!await requirePermission(req,res,"wallets.read"))return;const {data,error}=await db(req).from("wallets").select("*").order("created_at",{ascending:false}).limit(100);if(error)throw error;ok(res,data||[]);}catch(e){next(e);}});
app.get("/api/admin/wallets/:id", requireAdmin, async (req,res,next)=>{try{if(!await requirePermission(req,res,"wallets.read"))return;safeId.parse(req.params.id);const {data,error}=await db(req).from("wallets").select("*").eq("id",req.params.id).maybeSingle();if(error)throw error;if(!data)return fail(res,"NOT_FOUND","Wallet not found.",404);ok(res,data);}catch(e){next(e);}});

for (const [action, status, permission] of [["freeze","frozen","wallets.freeze"],["unfreeze","active","wallets.unfreeze"]]) {
  app.post(`/api/admin/wallets/:id/${action}`, requireAdmin, async (req,res,next)=>{
    try {if(!await requirePermission(req,res,permission))return;safeId.parse(req.params.id);const reason=z.object({reason:z.string().trim().min(3).max(240)}).parse(req.body).reason;const {data,error}=await db(req).from("wallets").update({status}).eq("id",req.params.id).select().single();if(error)throw error;await audit(req,`${action.toUpperCase()}_WALLET`,"wallet",req.params.id,reason);ok(res,data);}catch(e){next(e);}
  });
}

app.get("/api/admin/transactions", requireAdmin, async (req,res,next)=>{try{if(!await requirePermission(req,res,"transactions.read"))return;const {data,error}=await db(req).from("transactions").select("*").order("created_at",{ascending:false}).limit(100);if(error)throw error;ok(res,data||[]);}catch(e){next(e);}});
for(const [table,path,permission] of [["deposits","deposits","deposits.read"],["withdrawals","withdrawals","withdrawals.read"],["money_requests","requests.read","requests.read"],["payment_links","payment-links","payment_links.read"],["reconciliation_records","reconciliation","reconciliation.read"],["provider_webhook_events","webhooks","webhooks.read"],["security_events","security-events","security.read"],["device_sessions","sessions","sessions.read"]]){
  app.get(`/api/admin/${path}`,requireAdmin,async(req,res,next)=>{try{if(!await requirePermission(req,res,permission))return;const {data,error}=await db(req).from(table).select("*").order("created_at",{ascending:false}).limit(100);if(error)throw error;ok(res,data||[]);}catch(e){next(e);}});
}
app.get("/api/admin/ledger", requireAdmin, async(req,res,next)=>{try{if(!await requirePermission(req,res,"ledger.read"))return;const {data,error}=await db(req).from("ledger_entries").select("*").order("created_at",{ascending:false}).limit(100);if(error)throw error;ok(res,data||[]);}catch(e){next(e);}});
app.get("/api/admin/audit", requireAdmin, async(req,res,next)=>{try{if(!await requirePermission(req,res,"audit.read"))return;const {data,error}=await db(req).from("audit_logs").select("*").order("created_at",{ascending:false}).limit(100);if(error)throw error;ok(res,data||[]);}catch(e){next(e);}});
app.get("/api/admin/risk", requireAdmin, async(req,res,next)=>{try{if(!await requirePermission(req,res,"risk.read"))return;const {data,error}=await db(req).from("user_restrictions").select("*").eq("active",true).order("created_at",{ascending:false}).limit(100);if(error)throw error;ok(res,data||[]);}catch(e){next(e);}});
app.get("/api/admin/limits", requireAdmin, async(req,res,next)=>{try{if(!await requirePermission(req,res,"limits.read"))return;const {data,error}=await db(req).from("wallet_limits").select("*").limit(100);if(error)throw error;ok(res,data||[]);}catch(e){next(e);}});
app.get("/api/admin/fees", requireAdmin, async(req,res,next)=>{try{if(!await requirePermission(req,res,"fees.read"))return;const {data,error}=await db(req).from("fee_configurations").select("*").order("name");if(error)throw error;ok(res,data||[]);}catch(e){next(e);}});
app.get("/api/admin/permissions", requireAdmin, async(req,res,next)=>{try{if(!await requirePermission(req,res,"permissions.read"))return;const {data,error}=await db(req).from("admin_roles").select("id,name,description,admin_role_permissions(permission:admin_permissions(name))");if(error)throw error;ok(res,data||[]);}catch(e){next(e);}});
app.get("/api/admin/adjustments", requireAdmin, async(req,res,next)=>{try{if(!await requirePermission(req,res,"ledger.adjust"))return;const {data,error}=await db(req).from("audit_logs").select("*").eq("action","BALANCE_CREDIT").order("created_at",{ascending:false}).limit(100);if(error)throw error;ok(res,data||[]);}catch(e){next(e);}});
app.post("/api/admin/adjustments", requireAdmin, async(req,res,next)=>{try{if(!await requirePermission(req,res,"ledger.adjust"))return;const input=z.object({wallet_id:safeId,type:z.enum(["credit","debit","reserve","release"]),amount:money,reason:z.string().trim().min(3).max(240),reference:z.string().trim().min(3).max(80)}).parse(req.body);const {data,error}=await db(req).rpc("admin_adjust_wallet",{p_wallet_id:input.wallet_id,p_type:input.type,p_amount:input.amount,p_reason:input.reason,p_reference:input.reference,p_admin_user_id:req.user.id});if(error)throw error;ok(res,data,201);}catch(e){next(e);}});

app.get("/api/admin/notifications", requireAdmin, async(req,res,next)=>{try{if(!await requirePermission(req,res,"notifications.read"))return;const {data,error}=await db(req).from("notifications").select("*").order("created_at",{ascending:false}).limit(100);if(error)throw error;ok(res,data||[]);}catch(e){next(e);}});
app.get("/api/admin/reconciliation", requireAdmin, async(req,res,next)=>{try{if(!await requirePermission(req,res,"reconciliation.read"))return;const {data,error}=await db(req).from("reconciliation_records").select("*").order("created_at",{ascending:false}).limit(100);if(error)throw error;ok(res,data||[]);}catch(e){next(e);}});
app.get("/api/admin/security-events", requireAdmin, async(req,res,next)=>{try{if(!await requirePermission(req,res,"security.read"))return;const {data,error}=await db(req).from("security_events").select("*").order("created_at",{ascending:false}).limit(100);if(error)throw error;ok(res,data||[]);}catch(e){next(e);}});
app.get("/api/admin/sessions", requireAdmin, async(req,res,next)=>{try{if(!await requirePermission(req,res,"sessions.read"))return;const {data,error}=await db(req).from("device_sessions").select("*").order("last_seen_at",{ascending:false}).limit(100);if(error)throw error;ok(res,data||[]);}catch(e){next(e);}});
app.get("/api/admin/provider-status", requireAdmin, async(req,res,next)=>{try{if(!await requirePermission(req,res,"provider.read"))return;ok(res,{lipila:{connected:false,status:"not_configured"},webhooks:{configured:false}});}catch(e){next(e);}});
app.get("/api/admin/jobs", requireAdmin, async(req,res,next)=>{try{if(!await requirePermission(req,res,"jobs.read"))return;ok(res,{items:[],message:"No background job runner is configured yet."});}catch(e){next(e);}});

app.use((err, _req, res, _next) => {
  const status = err.status || 500;
  if (process.env.NODE_ENV !== "production") console.error(err.message);
  const known = err.name === "ZodError"
    ? { code: "VALIDATION_ERROR", message: "Please check the wallet details and try again." }
    : { code: status >= 500 ? "WALLET_SERVICE_ERROR" : (err.code || "REQUEST_ERROR"), message: status >= 500 ? "We could not complete that wallet request. Please try again shortly." : (err.message || "Please check the wallet details and try again.") };
  res.status(status).json({ success: false, error: known });
});

app.listen(port, () => console.info(`ZedMoney API listening on port ${port}`));