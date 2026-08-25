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
const supabaseUrl = process.env.SUPABASE_URL || "https://ogbllqeppeldaqfntwca.supabase.co";
const anonKey = process.env.SUPABASE_ANON_KEY || "sb_publishable_s9niKjtssyGDFvN3dvDD9A_pSrnrxig";
const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const publicClient = supabaseUrl && anonKey ? createClient(supabaseUrl, anonKey) : null;
const adminClient = supabaseUrl && serviceRoleKey ? createClient(supabaseUrl, serviceRoleKey) : null;
const adminSessions = new Map();
const adminTtlMs = Math.max(5, Number(process.env.ADMIN_SESSION_TTL_MINUTES || 120)) * 60 * 1000;
const cookieName = "zedmoney_admin";

// Lipila configuration. Keep the API key and webhook secret server-side only.
const lipilaEnvironment = String(process.env.LIPILA_ENVIRONMENT || "production").toLowerCase();
const lipilaBaseUrl = process.env.LIPILA_BASE_URL || (lipilaEnvironment === "sandbox" ? "https://api.lipila.dev" : "https://blz.lipila.io");
const lipilaApiKey = process.env.LIPILA_API_KEY || "";
const lipilaWebhookSecret = process.env.LIPILA_WEBHOOK_SECRET || "";
const lipilaCallbackUrl = process.env.LIPILA_CALLBACK_URL || "";
const withdrawalDelayMs = Math.max(1, Number(process.env.WITHDRAWAL_DELAY_HOURS || 24)) * 60 * 60 * 1000;
const workerIntervalMs = Math.max(30, Number(process.env.LIPILA_WORKER_INTERVAL_SECONDS || 60)) * 1000;

app.disable("x-powered-by");
app.use(helmet({ crossOriginResourcePolicy: { policy: "cross-origin" } }));
app.use(cors({
  // Temporary development policy: reflect every requesting browser origin.
  // This is compatible with credentials; "*" cannot be used with cookies.
  origin: true,
  credentials: true,
  methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "Idempotency-Key"]
}));
app.use(express.json({
  limit: "64kb",
  verify: (req, _res, buf) => { req.rawBody = Buffer.from(buf); }
}));
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


function normalizeProviderStatus(value) {
  return String(value || "").trim().toLowerCase();
}

function isProviderSuccess(value) {
  return ["successful", "success", "completed", "complete", "paid", "succeeded"].includes(normalizeProviderStatus(value));
}

function isProviderFailure(value) {
  return ["failed", "failure", "cancelled", "canceled", "reversed", "declined", "rejected"].includes(normalizeProviderStatus(value));
}

async function lipilaRequest(pathname, { method = "GET", body = undefined, headers = {} } = {}) {
  if (!lipilaApiKey) {
    throw Object.assign(new Error("Lipila is not configured on the server."), { status: 503, code: "LIPILA_NOT_CONFIGURED" });
  }
  const response = await fetch(`${lipilaBaseUrl}${pathname}`, {
    method,
    headers: {
      accept: "application/json",
      "x-api-key": lipilaApiKey,
      ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      ...(headers || {})
    },
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  const text = await response.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = { raw: text }; }
  if (!response.ok) {
    const message = data?.message || data?.error || `Lipila returned HTTP ${response.status}`;
    throw Object.assign(new Error(message), { status: response.status >= 500 ? 502 : response.status, code: `LIPILA_${response.status}`, providerResponse: data });
  }
  return data;
}

async function userOperationalState(req) {
  const client = db(req);
  const [{ data: profile, error: pe }, { data: wallet, error: we }] = await Promise.all([
    client.from("profiles").select("id,status").eq("id", req.user.id).maybeSingle(),
    client.from("wallets").select("id,status,currency,available_balance,pending_balance,reserved_balance").eq("user_id", req.user.id).maybeSingle()
  ]);
  if (pe) throw pe;
  if (we) throw we;
  if (!profile) throw Object.assign(new Error("User profile not found."), { status: 404, code: "PROFILE_NOT_FOUND" });
  if (profile.status === "suspended") throw Object.assign(new Error("Your account is suspended."), { status: 403, code: "ACCOUNT_SUSPENDED" });
  if (profile.status === "closed") throw Object.assign(new Error("Your account is closed."), { status: 403, code: "ACCOUNT_CLOSED" });
  if (!wallet) throw Object.assign(new Error("Wallet not found."), { status: 404, code: "WALLET_NOT_FOUND" });
  if (wallet.status === "frozen") throw Object.assign(new Error("Your wallet is frozen."), { status: 403, code: "WALLET_FROZEN" });
  if (wallet.status === "closed") throw Object.assign(new Error("Your wallet is closed."), { status: 403, code: "WALLET_CLOSED" });
  return { profile, wallet };
}

async function createNotification(userId, type, title, message, metadata = {}) {
  if (!adminClient) return;
  const { error } = await adminClient.from("notifications").insert({ user_id: userId, type, title, message, metadata });
  if (error) console.error("Notification insert failed:", error.message);
}

function verifyLipilaWebhook(req) {
  if (!lipilaWebhookSecret) return process.env.NODE_ENV !== "production";
  const id = req.get("webhook-id") || "";
  const timestamp = req.get("webhook-timestamp") || "";
  const signature = req.get("webhook-signature") || "";
  if (!id || !timestamp || !signature || !req.rawBody) return false;
  const age = Math.abs(Date.now() / 1000 - Number(timestamp));
  if (!Number.isFinite(age) || age > 300) return false;
  let key;
  try { key = Buffer.from(lipilaWebhookSecret.replace(/^whsec_/, ""), "base64"); } catch { return false; }
  const signed = `${id}.${timestamp}.${req.rawBody.toString("utf8")}`;
  const expected = "v1," + crypto.createHmac("sha256", key).update(signed).digest("base64");
  return signature.split(" ").some(sig => {
    const a = Buffer.from(expected);
    const b = Buffer.from(sig.trim());
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  });
}

async function recordProviderWebhook(eventId, eventType, payload, signature, transactionId = null) {
  const { data, error } = await adminClient.from("provider_webhook_events").insert({
    provider: "lipila", event_id: eventId, event_type: eventType || null,
    transaction_id: transactionId, payload, signature: signature || null
  }).select("id").maybeSingle();
  if (error) {
    if (error.code === "23505") return { duplicate: true };
    throw error;
  }
  return { duplicate: false, id: data?.id };
}

async function applyLipilaCollectionCallback(payload, webhookEventId) {
  const referenceId = payload.referenceId || payload.reference_id || payload.identifier;
  if (!referenceId) throw Object.assign(new Error("Lipila callback has no referenceId/identifier."), { status: 400, code: "LIPILA_BAD_CALLBACK" });
  const status = payload.status;
  const providerReference = payload.identifier || payload.externalId || referenceId;
  const { data: tx, error: te } = await adminClient.from("transactions").select("*").eq("provider", "lipila").eq("provider_reference", referenceId).maybeSingle();
  if (te) throw te;
  let transaction = tx;
  if (!transaction) {
    const { data: byIdentifier, error: ie } = await adminClient.from("transactions").select("*").eq("provider", "lipila").eq("provider_reference", providerReference).maybeSingle();
    if (ie) throw ie;
    transaction = byIdentifier;
  }
  if (!transaction) return { ignored: true, reason: "unknown_transaction" };

  const normalized = normalizeProviderStatus(status);
  const success = isProviderSuccess(normalized);
  const failure = isProviderFailure(normalized);
  if (!success && !failure) return { ignored: true, reason: "non_terminal_status" };

  const { data: currentDeposit, error: de } = await adminClient.from("deposits").select("*").eq("id", transaction.metadata?.deposit_id || "00000000-0000-0000-0000-000000000000").maybeSingle();
  if (de) throw de;
  const paymentLinkPaymentId = transaction.metadata?.payment_link_payment_id;

  // Idempotent terminal processing: once the internal transaction is terminal, do not credit twice.
  if (["successful", "failed", "reversed", "cancelled"].includes(transaction.status)) {
    return { already_processed: true, status: transaction.status };
  }

  const now = new Date().toISOString();
  const depositId = currentDeposit?.id || transaction.metadata?.deposit_id;
  if (depositId) {
    const { error } = await adminClient.from("deposits").update({
      status: success ? "successful" : "failed", provider: "lipila", provider_reference: providerReference, updated_at: now
    }).eq("id", depositId);
    if (error) throw error;
  }
  if (paymentLinkPaymentId) {
    const { error } = await adminClient.from("payment_link_payments").update({
      status: success ? "successful" : "failed", provider: "lipila", provider_reference: providerReference
    }).eq("id", paymentLinkPaymentId);
    if (error) throw error;
  }

  if (success) {
    const { data: wallet, error: we } = await adminClient.from("wallets").select("*").eq("user_id", transaction.user_id).maybeSingle();
    if (we) throw we;
    if (!wallet) throw Object.assign(new Error("Wallet not found for Lipila collection."), { status: 404, code: "WALLET_NOT_FOUND" });
    const before = Number(wallet.available_balance);
    const after = before + Number(transaction.net_amount || transaction.amount);
    const { error: wu } = await adminClient.from("wallets").update({ available_balance: after, updated_at: now }).eq("id", wallet.id);
    if (wu) throw wu;
    const { error: tu } = await adminClient.from("transactions").update({ status: "successful", provider_reference: providerReference, completed_at: now, updated_at: now }).eq("id", transaction.id);
    if (tu) throw tu;
    const { error: le } = await adminClient.from("ledger_entries").insert({ wallet_id: wallet.id, transaction_id: transaction.id, entry_type: "deposit", direction: "credit", amount: transaction.net_amount || transaction.amount, currency: transaction.currency, balance_before: before, balance_after: after, reference: transaction.reference, description: transaction.description || "Lipila deposit", metadata: { webhook_event_id: webhookEventId, provider_reference: providerReference } });
    if (le) throw le;
    await createNotification(transaction.user_id, "deposit_success", "Deposit successful", `${transaction.currency} ${Number(transaction.net_amount || transaction.amount).toFixed(2)} has been added to your wallet.`, { transaction_id: transaction.id, provider_reference: providerReference });
    return { processed: true, status: "successful", transaction_id: transaction.id };
  }

  const { error: tf } = await adminClient.from("transactions").update({ status: "failed", provider_reference: providerReference, completed_at: now, updated_at: now }).eq("id", transaction.id);
  if (tf) throw tf;
  await createNotification(transaction.user_id, "deposit_failed", "Deposit failed", payload.message || "Your Lipila deposit could not be completed.", { transaction_id: transaction.id, provider_reference: providerReference });
  return { processed: true, status: "failed", transaction_id: transaction.id };
}

async function processDueWithdrawals() {
  if (!adminClient || !lipilaApiKey) return;
  const cutoff = new Date(Date.now() - withdrawalDelayMs).toISOString();
  const { data: rows, error } = await adminClient.from("withdrawals")
    .select("*, profile:profiles!inner(id,status)")
    .eq("status", "pending").is("provider_reference", null).lte("created_at", cutoff).limit(25);
  if (error) { console.error("Withdrawal worker lookup failed:", error.message); return; }
  for (const w of rows || []) {
    try {
      const { data: tx, error: txError } = await adminClient.from("transactions").select("id,reference,status,description,net_amount,provider_reference,wallet_id,metadata").eq("user_id", w.user_id).eq("type", "withdrawal").eq("metadata->>withdrawal_id", w.id).maybeSingle();
      if (txError) throw txError;
      if (!tx) { console.error("Withdrawal transaction not found:", w.id); continue; }
      w.transaction = tx;
      if (w.profile?.status === "suspended" || w.profile?.status === "closed") {
        await failWithdrawal(w, "Account is suspended or closed; withdrawal was not sent.");
        continue;
      }
      const ref = w.transaction?.reference || `WAITAPP-ORD-${w.id}`;
      let providerResponse;
      if (w.method === "mobile_money") {
        providerResponse = await lipilaRequest("/api/v1/disbursements/mobile-money", {
          method: "POST",
          headers: lipilaCallbackUrl ? { callbackUrl: lipilaCallbackUrl } : {},
          body: { referenceId: ref, amount: Number(w.amount), accountNumber: w.destination, currency: w.currency, narration: w.transaction?.description || "ZedMoney withdrawal", referenceData: ref }
        });
      } else {
        // The currently published Lipila docs verify mobile-money disbursement. Do not invent a bank endpoint.
        await failWithdrawal(w, "Bank disbursements are not enabled because the configured Lipila integration only supports the verified mobile-money endpoint.");
        continue;
      }
      const providerReference = providerResponse?.referenceId || providerResponse?.identifier || ref;
      const providerStatus = providerResponse?.status || "Pending";
      w.provider_reference = providerReference;
      if (isProviderSuccess(providerStatus)) {
        const now = new Date().toISOString();
        const { error: wu } = await adminClient.from("withdrawals").update({ status: "successful", provider: "lipila", provider_reference: providerReference, updated_at: now }).eq("id", w.id).eq("status", "pending");
        if (wu) throw wu;
        const { error: tu } = await adminClient.from("transactions").update({ status: "successful", provider: "lipila", provider_reference: providerReference, completed_at: now, updated_at: now }).eq("id", w.transaction.id);
        if (tu) throw tu;
        await settleSuccessfulWithdrawal(w);
      } else if (isProviderFailure(providerStatus)) {
        // A provider rejection must release the reserved funds. Previously the
        // worker marked the withdrawal failed but left the money reserved.
        await failWithdrawal(w, providerResponse?.message || "Lipila could not complete the withdrawal.");
      } else {
        const now = new Date().toISOString();
        const { error: wu } = await adminClient.from("withdrawals").update({ status: "processing", provider: "lipila", provider_reference: providerReference, updated_at: now }).eq("id", w.id).eq("status", "pending");
        if (wu) throw wu;
        const { error: tu } = await adminClient.from("transactions").update({ status: "processing", provider: "lipila", provider_reference: providerReference, updated_at: now }).eq("id", w.transaction.id);
        if (tu) throw tu;
        await createNotification(w.user_id, "withdrawal_processing", "Withdrawal processing", "Your 24-hour withdrawal hold has completed and Lipila is processing the payout.", { withdrawal_id: w.id, provider_reference: providerReference });
      }
    } catch (e) {
      console.error("Lipila withdrawal dispatch failed:", w.id, e.message);
      // Keep the withdrawal pending for retry unless Lipila explicitly rejected the request.
      if (e.status && e.status < 500) await failWithdrawal(w, e.message);
    }
  }
}

async function settleSuccessfulWithdrawal(w) {
  const now = new Date().toISOString();
  const { data: wallet, error } = await adminClient.from("wallets").select("*").eq("user_id", w.user_id).maybeSingle();
  if (error) throw error;
  if (!wallet) throw new Error("Wallet not found");
  const before = Number(wallet.reserved_balance || 0);
  const after = Math.max(0, before - Number(w.amount));
  const { error: wu } = await adminClient.from("wallets").update({ reserved_balance: after, updated_at: now }).eq("id", wallet.id);
  if (wu) throw wu;
  const { error: le } = await adminClient.from("ledger_entries").insert({ wallet_id: wallet.id, transaction_id: w.transaction.id, entry_type: "withdrawal_settlement", direction: "debit", amount: w.amount, currency: w.currency, balance_before: before, balance_after: after, reference: w.transaction.reference, description: "Lipila withdrawal settled", metadata: { provider_reference: w.provider_reference } });
  if (le) throw le;
  await createNotification(w.user_id, "withdrawal_success", "Withdrawal successful", `${w.currency} ${Number(w.amount).toFixed(2)} has been sent through Lipila.`, { withdrawal_id: w.id, provider_reference: w.provider_reference });
}

async function failWithdrawal(w, message) {
  const now = new Date().toISOString();
  const { data: wallet, error } = await adminClient.from("wallets").select("*").eq("user_id", w.user_id).maybeSingle();
  if (error) throw error;
  if (!wallet) throw new Error("Wallet not found");
  const beforeReserved = Number(wallet.reserved_balance || 0);
  const amount = Number(w.amount);
  const newReserved = Math.max(0, beforeReserved - amount);
  const newAvailable = Number(wallet.available_balance) + amount;
  const { error: wu } = await adminClient.from("wallets").update({ available_balance: newAvailable, reserved_balance: newReserved, updated_at: now }).eq("id", wallet.id);
  if (wu) throw wu;
  await adminClient.from("withdrawals").update({ status: "failed", updated_at: now }).eq("id", w.id);
  await adminClient.from("transactions").update({ status: "failed", completed_at: now, updated_at: now }).eq("id", w.transaction.id);
  await adminClient.from("ledger_entries").insert({ wallet_id: wallet.id, transaction_id: w.transaction.id, entry_type: "withdrawal_release", direction: "credit", amount, currency: w.currency, balance_before: newAvailable - amount, balance_after: newAvailable, reference: w.transaction.reference, description: message });
  await createNotification(w.user_id, "withdrawal_failed", "Withdrawal failed", message, { withdrawal_id: w.id });
}

function bearer(req) {
  const value = req.get("authorization") || "";
  return value.startsWith("Bearer ") ? value.slice(7) : null;
}

function cookies(req) {
  return Object.fromEntries((req.get("cookie") || "").split(";").map(v => v.trim().split("=")).filter(v => v.length === 2));
}

function adminCookie(res, value, maxAge) {
  // The admin page is hosted separately from this API on Render. A cookie
  // created by a cross-origin fetch must be SameSite=None and Secure or the
  // browser will silently omit it on the next /api/admin request.
  const production = process.env.NODE_ENV === "production";
  const crossOrigin = production || process.env.RENDER === "true" || process.env.COOKIE_CROSS_SITE === "true";
  const cookieAttributes = crossOrigin
    ? "; HttpOnly; SameSite=None; Secure"
    : "; HttpOnly; SameSite=Lax";
  res.setHeader("Set-Cookie", `${cookieName}=${value}; Path=/; Max-Age=${maxAge}${cookieAttributes}`);
}

function passwordMatches(password) {
  // Temporary bootstrap password. Replace ADMIN_PASSWORD with a secret or
  // ADMIN_PASSWORD_HASH before production.
  const temporaryPassword = process.env.ADMIN_PASSWORD || "3462";
  if (password && password === temporaryPassword) return true;
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



app.post("/api/webhooks/lipila", async (req, res) => {
  try {
    if (!verifyLipilaWebhook(req)) return fail(res, "INVALID_WEBHOOK_SIGNATURE", "Invalid Lipila webhook signature.", 401);
    const payload = req.body || {};
    const eventId = req.get("webhook-id") || payload.referenceId || payload.identifier || crypto.createHash("sha256").update(req.rawBody || JSON.stringify(payload)).digest("hex");
    const eventType = `${payload.type || "transaction"}.${normalizeProviderStatus(payload.status) || "updated"}`;
    const recorded = await recordProviderWebhook(eventId, eventType, payload, req.get("webhook-signature"));
    if (recorded.duplicate) return ok(res, { received: true, duplicate: true });
    let result = { ignored: true };
    if (String(payload.type || "").toLowerCase() === "collection") result = await applyLipilaCollectionCallback(payload, eventId);
    else if (String(payload.type || "").toLowerCase() === "disbursement") {
      const reference = payload.referenceId || payload.identifier;
      const { data: tx, error } = await adminClient.from("transactions").select("*").eq("provider", "lipila").eq("provider_reference", reference).maybeSingle();
      if (error) throw error;
      if (tx) {
        const { data: withdrawal, error: we } = await adminClient.from("withdrawals").select("*").eq("id", tx.metadata?.withdrawal_id || "00000000-0000-0000-0000-000000000000").maybeSingle();
        if (we) throw we;
        if (withdrawal) {
          if (isProviderSuccess(payload.status) && tx.status !== "successful") {
            await adminClient.from("withdrawals").update({ status: "successful", provider_reference: reference, updated_at: new Date().toISOString() }).eq("id", withdrawal.id);
            await adminClient.from("transactions").update({ status: "successful", completed_at: new Date().toISOString(), updated_at: new Date().toISOString() }).eq("id", tx.id);
            await settleSuccessfulWithdrawal({ ...withdrawal, transaction: tx, provider_reference: reference });
          } else if (isProviderFailure(payload.status) && tx.status !== "failed") {
            await failWithdrawal({ ...withdrawal, transaction: tx }, payload.message || "Lipila could not complete the withdrawal.");
          }
          result = { processed: true, transaction_id: tx.id };
        }
      }
    }
    await adminClient.from("provider_webhook_events").update({ transaction_id: result.transaction_id || null, processed_at: new Date().toISOString(), processing_status: "processed" }).eq("provider", "lipila").eq("event_id", eventId);
    return ok(res, { received: true, result });
  } catch (e) {
    console.error("Lipila webhook error:", e.message);
    return fail(res, "LIPILA_WEBHOOK_ERROR", "Webhook received but could not be processed.", 500);
  }
});

app.get("/api/health", (_req, res) => ok(res, { ok: true, service: "zedmoney-api" }));

app.post("/api/admin/login", async (req, res) => {
  const password = typeof req.body?.password === "string" ? req.body.password : "";
  if (!passwordMatches(password)) return fail(res, "INVALID_ADMIN_CREDENTIALS", "The admin password is incorrect.", 401);
  const userId = process.env.ADMIN_SYSTEM_USER_ID;
  if (!userId || !adminClient) {
    const missing = [
      !serviceRoleKey && "SUPABASE_SERVICE_ROLE_KEY",
      !userId && "ADMIN_SYSTEM_USER_ID"
    ].filter(Boolean).join(" and ");
    return fail(res, "WALLET_SERVICE_ERROR", `Supabase administrator configuration is missing: ${missing || "unknown configuration"}.`, 503);
  }
  const { data: admin, error } = await adminClient
    .from("admin_users")
    .select("id,user_id,active,role_id")
    .eq("user_id", userId)
    .maybeSingle();
  if (error) {
    console.error("Admin Supabase lookup failed:", error);
    return fail(res, "WALLET_SERVICE_ERROR", `Supabase admin lookup failed${error.code ? ` (${error.code})` : ""}: ${error.message || "unknown database error"}`, 503);
  }
  if (!admin) return fail(res, "FORBIDDEN", "No admin_users record exists for ADMIN_SYSTEM_USER_ID.", 403);
  if (admin.active === false) return fail(res, "FORBIDDEN", "The configured administrator account is inactive in admin_users.", 403);
  const token = crypto.randomBytes(32).toString("base64url");
  adminSessions.set(token, { userId: userId || admin.user_id, adminId: admin.id, roleId: admin.role_id, expiresAt: Date.now() + adminTtlMs });
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
    await userOperationalState(req);
    const input = z.object({
      amount: money,
      currency: z.string().length(3).default("ZMW"),
      method: z.enum(["mobile_money", "card", "ussd", "payment_link"]),
      accountNumber: z.string().trim().min(7).max(32),
      description: z.string().max(240).optional(),
      email: z.string().email().optional(),
      referenceData: z.string().max(240).optional()
    }).parse(req.body);
    if (input.method !== "mobile_money") return fail(res, "LIPILA_METHOD_NOT_ENABLED", "This Lipila integration currently processes mobile-money collections. Card/USSD collection requires the corresponding Lipila merchant configuration.", 422);
    const key = req.get("Idempotency-Key");
    if (!key) return fail(res, "IDEMPOTENCY_KEY_REQUIRED", "Idempotency-Key is required.", 400);
    const { data: existing } = await db(req).from("deposits").select("*").eq("user_id", req.user.id).eq("idempotency_key", key).maybeSingle();
    if (existing) return ok(res, existing);
    const referenceId = `WAITAPP-ORD-${crypto.randomUUID()}`;
    const { data: deposit, error: de } = await db(req).from("deposits").insert({ user_id: req.user.id, amount: input.amount, currency: input.currency, method: input.method, status: "pending", provider: "lipila", description: input.description || null, idempotency_key: key }).select().single();
    if (de) throw de;
    const { data: tx, error: te } = await db(req).from("transactions").insert({ reference: referenceId, user_id: req.user.id, wallet_id: (await userOperationalState(req)).wallet.id, type: "deposit", status: "pending", amount: input.amount, fee: 0, net_amount: input.amount, currency: input.currency, description: input.description || "Lipila deposit", provider: "lipila", provider_reference: referenceId, idempotency_key: key, metadata: { deposit_id: deposit.id, account_number: input.accountNumber } }).select().single();
    if (te) throw te;
    const provider = await lipilaRequest("/api/v1/collections/mobile-money", {
      method: "POST",
      headers: lipilaCallbackUrl ? { callbackUrl: lipilaCallbackUrl } : {},
      body: { referenceId, amount: Number(input.amount), narration: input.description || "ZedMoney deposit", accountNumber: input.accountNumber, currency: input.currency, email: input.email || req.user.email || undefined, referenceData: input.referenceData || referenceId }
    });
    const providerReference = provider?.referenceId || provider?.identifier || referenceId;
    const providerStatus = provider?.status || "Pending";
    // Leave terminal state changes to the common callback handler so a
    // synchronous successful response is credited exactly once.
    await db(req).from("deposits").update({ provider_reference: providerReference, updated_at: new Date().toISOString() }).eq("id", deposit.id);
    await db(req).from("transactions").update({ provider_reference: providerReference, updated_at: new Date().toISOString() }).eq("id", tx.id);
    if (isProviderSuccess(providerStatus)) {
      await applyLipilaCollectionCallback({ referenceId, identifier: providerReference, status: "Successful", amount: input.amount, currency: input.currency, type: "Collection", message: "Lipila collection completed" }, `sync-${referenceId}`);
    } else if (isProviderFailure(providerStatus)) {
      await createNotification(req.user.id, "deposit_failed", "Deposit failed", provider?.message || "Lipila could not start the deposit.", { transaction_id: tx.id });
    } else {
      await createNotification(req.user.id, "deposit_pending", "Deposit pending", "Approve the Lipila mobile-money prompt to complete your deposit.", { transaction_id: tx.id, provider_reference: providerReference });
    }
    ok(res, { deposit, transaction: tx, provider }, 201);
  } catch (e) { next(e); }
});
app.get("/api/deposits", requireAuth, async (req, res, next) => { try { const { data, error } = await db(req).from("deposits").select("*").eq("user_id", req.user.id).order("created_at", { ascending: false }); if (error) throw error; ok(res, data || []); } catch (e) { next(e); } });
app.get("/api/deposits/:id", requireAuth, async (req, res, next) => { try { const data = await owned(req, "deposits", req.params.id); if (!data) return fail(res, "NOT_FOUND", "Deposit not found.", 404); ok(res, data); } catch (e) { next(e); } });

app.post("/api/withdrawals", requireAuth, async (req, res, next) => {
  try {
    const state = await userOperationalState(req);
    const input = z.object({ amount: money, currency: z.string().length(3).default(state.wallet.currency), method: z.enum(["mobile_money", "bank_account"]), destination: z.string().trim().min(7).max(160) }).parse(req.body);
    if (input.currency !== state.wallet.currency) return fail(res, "CURRENCY_MISMATCH", "Withdrawal currency does not match your wallet currency.", 400);
    const key = req.get("Idempotency-Key"); if (!key) return fail(res, "IDEMPOTENCY_KEY_REQUIRED", "Idempotency-Key is required.", 400);
    const existing = await db(req).from("withdrawals").select("*").eq("user_id", req.user.id).eq("idempotency_key", key).maybeSingle();
    if (existing.data) return ok(res, existing.data);
    if (Number(state.wallet.available_balance) < Number(input.amount)) return fail(res, "INSUFFICIENT_BALANCE", "Insufficient available balance.", 409);
    if (input.method !== "mobile_money") return fail(res, "LIPILA_METHOD_NOT_ENABLED", "The configured Lipila integration currently supports mobile-money disbursement only.", 422);
    // Reserve immediately; actual Lipila disbursement is intentionally delayed for 24 hours.
    const reference = `WAITAPP-ORD-${crypto.randomUUID()}`;
    const now = new Date().toISOString();
    const newAvailable = Number(state.wallet.available_balance) - Number(input.amount);
    const newReserved = Number(state.wallet.reserved_balance || 0) + Number(input.amount);
    const { data: tx, error: te } = await db(req).from("transactions").insert({ reference, user_id: req.user.id, wallet_id: state.wallet.id, type: "withdrawal", status: "pending", amount: input.amount, fee: 0, net_amount: input.amount, currency: input.currency, description: "Mobile-money withdrawal (24-hour hold)", provider: "lipila", idempotency_key: key, metadata: { withdrawal_pending_until: new Date(Date.now() + withdrawalDelayMs).toISOString() } }).select().single();
    if (te) throw te;
    const { data: withdrawal, error: we } = await db(req).from("withdrawals").insert({ user_id: req.user.id, amount: input.amount, currency: input.currency, method: input.method, destination: input.destination, status: "pending", provider: "lipila", idempotency_key: key }).select().single();
    if (we) throw we;
    await db(req).from("transactions").update({ provider_reference: reference, metadata: { withdrawal_id: withdrawal.id, withdrawal_pending_until: new Date(Date.now() + withdrawalDelayMs).toISOString() } }).eq("id", tx.id);
    const { error: wu } = await db(req).from("wallets").update({ available_balance: newAvailable, reserved_balance: newReserved, updated_at: now }).eq("id", state.wallet.id);
    if (wu) throw wu;
    const { error: le } = await db(req).from("ledger_entries").insert({ wallet_id: state.wallet.id, transaction_id: tx.id, entry_type: "withdrawal_reserve", direction: "debit", amount: input.amount, currency: input.currency, balance_before: state.wallet.available_balance, balance_after: newAvailable, reference: tx.reference, description: "Funds reserved for 24-hour withdrawal hold" });
    if (le) throw le;
    await createNotification(req.user.id, "withdrawal_scheduled", "Withdrawal scheduled", `Your withdrawal will be submitted to Lipila after 24 hours.`, { withdrawal_id: withdrawal.id, available_at: new Date(Date.now() + withdrawalDelayMs).toISOString() });
    ok(res, { withdrawal_id: withdrawal.id, transaction_id: tx.id, reference: tx.reference, status: "pending", scheduled_for: new Date(Date.now() + withdrawalDelayMs).toISOString() }, 201);
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

app.get("/api/payment-links/public/:code", async (req, res, next) => {
  try {
    const { data, error } = await adminClient.from("payment_links").select("code,amount,currency,description,status,expires_at,view_count").eq("code", req.params.code).maybeSingle();
    if (error) throw error;
    if (!data) return fail(res, "NOT_FOUND", "Payment link not found.", 404);
    if (data.status !== "active") return fail(res, "PAYMENT_LINK_INACTIVE", "This payment link is no longer active.", 409);
    if (data.expires_at && new Date(data.expires_at) <= new Date()) return fail(res, "PAYMENT_LINK_EXPIRED", "This payment link has expired.", 409);
    await adminClient.from("payment_links").update({ view_count: Number(data.view_count || 0) + 1 }).eq("code", req.params.code);
    ok(res, data);
  } catch (e) { next(e); }
});

app.post("/api/payment-links/:code/pay", async (req, res, next) => {
  try {
    const input = z.object({ accountNumber: z.string().trim().min(7).max(32), amount: money.optional(), email: z.string().email().optional() }).parse(req.body);
    const { data: link, error: le } = await adminClient.from("payment_links").select("*").eq("code", req.params.code).maybeSingle();
    if (le) throw le;
    if (!link) return fail(res, "NOT_FOUND", "Payment link not found.", 404);
    if (link.status !== "active") return fail(res, "PAYMENT_LINK_INACTIVE", "This payment link is no longer active.", 409);
    if (link.expires_at && new Date(link.expires_at) <= new Date()) return fail(res, "PAYMENT_LINK_EXPIRED", "This payment link has expired.", 409);
    const ownerState = await adminClient.from("wallets").select("id,status,currency").eq("user_id", link.owner_id).maybeSingle();
    if (ownerState.data?.status !== "active") return fail(res, "WALLET_UNAVAILABLE", "The recipient wallet is not available.", 409);
    const amount = input.amount || Number(link.amount);
    if (input.amount && Number(input.amount) !== Number(link.amount)) return fail(res, "INVALID_AMOUNT", "This payment link requires the exact amount shown.", 400);
    const referenceId = `WAITAPP-ORD-${crypto.randomUUID()}`;
    const { data: payment, error: pe } = await adminClient.from("payment_link_payments").insert({ payment_link_id: link.id, amount, status: "pending", provider: "lipila", provider_reference: referenceId }).select().single();
    if (pe) throw pe;
    const { data: tx, error: te } = await adminClient.from("transactions").insert({ reference: referenceId, user_id: link.owner_id, wallet_id: ownerState.data.id, type: "payment_link", status: "pending", amount, fee: 0, net_amount: amount, currency: link.currency, description: link.description, payment_link_id: link.id, provider: "lipila", provider_reference: referenceId, metadata: { payment_link_payment_id: payment.id } }).select().single();
    if (te) throw te;
    const provider = await lipilaRequest("/api/v1/collections/mobile-money", { method: "POST", headers: lipilaCallbackUrl ? { callbackUrl: lipilaCallbackUrl } : {}, body: { referenceId, amount, narration: link.description, accountNumber: input.accountNumber, currency: link.currency, email: input.email, referenceData: `payment-link:${link.code}` } });
    const providerReference = provider?.referenceId || provider?.identifier || referenceId;
    // Keep the transaction pending until the callback handler performs the
    // wallet and ledger mutation.
    await adminClient.from("payment_link_payments").update({ transaction_id: tx.id }).eq("id", payment.id);
    await adminClient.from("payment_link_payments").update({ provider_reference: providerReference }).eq("id", payment.id);
    await adminClient.from("transactions").update({ provider_reference: providerReference }).eq("id", tx.id);
    if (isProviderSuccess(provider?.status)) await applyLipilaCollectionCallback({ referenceId, identifier: providerReference, status: "Successful", type: "Collection", amount, currency: link.currency, message: "Payment link payment completed" }, `sync-${referenceId}`);
    await adminClient.from("payment_links").update({ payment_count: Number(link.payment_count || 0) + (isProviderSuccess(provider?.status) ? 1 : 0), updated_at: new Date().toISOString() }).eq("id", link.id);
    ok(res, { payment, transaction: tx, provider }, 201);
  } catch (e) { next(e); }
});
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
     const {data,error}=await q;if(error)throw error;
     const ids=(data||[]).map(p=>p.id);
     const {data:wallets,error:walletError}=ids.length?await db(req).from("wallets").select("user_id,wallet_identifier,currency,available_balance,pending_balance,reserved_balance,status").in("user_id",ids):{data:[],error:null};
     if(walletError)throw walletError;
     const byUser=new Map((wallets||[]).map(w=>[w.user_id,w]));
      ok(res,(data||[]).map(p=>{
        const wallet=byUser.get(p.id)||{};
        return {...p,...wallet,status:p.status,wallet_status:wallet.status||null};
      }));
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
app.get("/api/admin/provider-status", requireAdmin, async(req,res,next)=>{try{if(!await requirePermission(req,res,"provider.read"))return;let lipila=null;try{lipila=await lipilaRequest("/api/v1/merchants/balance");}catch(e){lipila={error:e.message};}ok(res,{lipila:{environment:lipilaEnvironment,base_url:lipilaBaseUrl,configured:Boolean(lipilaApiKey),webhook_configured:Boolean(lipilaWebhookSecret),balance:lipila},webhooks:{configured:Boolean(lipilaWebhookSecret)}});}catch(e){next(e);}});
app.get("/api/admin/jobs", requireAdmin, async(req,res,next)=>{try{if(!await requirePermission(req,res,"jobs.read"))return;const cutoff=new Date(Date.now()-withdrawalDelayMs).toISOString();const {data,error}=await db(req).from("withdrawals").select("id,user_id,amount,currency,status,created_at,provider_reference").eq("status","pending").lte("created_at",cutoff).limit(100);if(error)throw error;ok(res,{withdrawal_delay_hours:withdrawalDelayMs/3600000,due_withdrawals:data||[],worker_interval_seconds:workerIntervalMs/1000});}catch(e){next(e);}});

app.use((err, _req, res, _next) => {
  const status = err.status || 500;
  if (process.env.NODE_ENV !== "production") console.error(err.message);
  const known = err.name === "ZodError"
    ? { code: "VALIDATION_ERROR", message: "Please check the wallet details and try again." }
    : { code: status >= 500 ? "WALLET_SERVICE_ERROR" : (err.code || "REQUEST_ERROR"), message: status >= 500 ? "We could not complete that wallet request. Please try again shortly." : (err.message || "Please check the wallet details and try again.") };
  res.status(status).json({ success: false, error: known });
});

const lipilaWorker = setInterval(() => processDueWithdrawals().catch(e => console.error("Lipila worker error:", e.message)), workerIntervalMs);
lipilaWorker.unref?.();
processDueWithdrawals().catch(e => console.error("Initial Lipila worker error:", e.message));

app.listen(port, () => console.info(`ZedMoney API listening on port ${port} (Lipila ${lipilaEnvironment})`));