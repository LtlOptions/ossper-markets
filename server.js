const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { Pool } = require("pg");
const crypto = require("crypto");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
const ADMIN_KEY = process.env.OSSPER_ADMIN_KEY;
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID || "";
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET || "";
const DISCORD_REDIRECT_URI = process.env.DISCORD_REDIRECT_URI || "";
const AUTH_SECRET = process.env.OSSPER_AUTH_SECRET || ADMIN_KEY;
const ADMIN_BOOTSTRAP_ENABLED = Boolean(ADMIN_KEY);
const DISCORD_AUTH_ENABLED = Boolean(DISCORD_CLIENT_ID && DISCORD_CLIENT_SECRET && DISCORD_REDIRECT_URI);

if (!DATABASE_URL) {
  console.error("DATABASE_URL is missing.");
  process.exit(1);
}
if (!ADMIN_KEY) {
  console.error("OSSPER_ADMIN_KEY is missing.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL.includes("railway") ? { rejectUnauthorized: false } : undefined,
});

app.set("trust proxy", 1);
app.use(helmet({
  contentSecurityPolicy: false,
}));
app.use(express.json({ limit: "100kb" }));
app.use(rateLimit({
  windowMs: 60 * 1000,
  max: 180,
  standardHeaders: true,
  legacyHeaders: false,
}));

const publicDir = __dirname;

function makeToken(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = crypto.createHmac("sha256", ADMIN_KEY).update(body).digest("base64url");
  return `${body}.${sig}`;
}

function readToken(token) {
  try {
    const [body, sig] = String(token || "").split(".");
    if (!body || !sig) return null;
    const expected = crypto.createHmac("sha256", ADMIN_KEY).update(body).digest("base64url");
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
    const payload = JSON.parse(Buffer.from(body, "base64url").toString());
    if (!payload.exp || payload.exp < Date.now()) return null;
    return payload;
  } catch {
    return null;
  }
}

function adminCookie(req) {
  const raw = req.headers.cookie || "";
  const match = raw.split(";").map(v => v.trim()).find(v => v.startsWith("ossper_admin="));
  return match ? decodeURIComponent(match.slice("ossper_admin=".length)) : null;
}

async function adminOnly(req, res, next) {
  const token = req.headers.authorization?.replace(/^Bearer\s+/i, "") || adminCookie(req);
  const payload = readToken(token);
  if (payload) {
    req.admin = { ...payload, source: "admin_key" };
    return next();
  }

  try {
    const accountId = await sessionAccountId(req);
    if (!accountId) return res.status(401).json({ error: "Admin authentication required." });
    const q = await pool.query(`
      SELECT a.id, a.discord_id, ar.role
      FROM accounts a
      JOIN admin_roles ar ON ar.discord_id=a.discord_id AND ar.revoked_at IS NULL
      WHERE a.id=$1
      ORDER BY CASE ar.role WHEN 'owner' THEN 1 WHEN 'admin' THEN 2 ELSE 9 END
      LIMIT 1
    `, [accountId]);
    if (!q.rows.length) return res.status(403).json({ error: "Your Discord account is not an Ossper admin." });
    req.admin = { role: q.rows[0].role, source: "discord", accountId: q.rows[0].id, discordId: q.rows[0].discord_id };
    next();
  } catch (e) {
    res.status(500).json({ error: "Admin authentication check failed." });
  }
}

async function ownerOnly(req, res, next) {
  if (req.admin?.source === "admin_key") return next();
  if (req.admin?.role === "owner") return next();
  return res.status(403).json({ error: "Owner access required." });
}

function setAdminCookie(res, token) {
  res.setHeader("Set-Cookie", `ossper_admin=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=28800`);
}

function hashToken(token) {
  return crypto.createHash("sha256").update(String(token)).digest("hex");
}

function makeAuthState(accountId = null, returnTo = "/#markets") {
  const safeReturn = returnTo === "/admin" ? "/admin" : "/#markets";
  const payload = { nonce: crypto.randomBytes(18).toString("hex"), exp: Date.now() + 10 * 60 * 1000, accountId: accountId || null, returnTo: safeReturn };
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = crypto.createHmac("sha256", AUTH_SECRET).update(body).digest("base64url");
  return `${body}.${sig}`;
}

function readAuthState(state) {
  try {
    const [body, sig] = String(state || "").split(".");
    if (!body || !sig) return null;
    const expected = crypto.createHmac("sha256", AUTH_SECRET).update(body).digest("base64url");
    if (sig.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
    const payload = JSON.parse(Buffer.from(body, "base64url").toString());
    if (!payload.exp || payload.exp < Date.now()) return null;
    return payload;
  } catch { return null; }
}

function cookieValue(req, name) {
  const raw = req.headers.cookie || "";
  const match = raw.split(";").map(v => v.trim()).find(v => v.startsWith(`${name}=`));
  return match ? decodeURIComponent(match.slice(name.length + 1)) : null;
}

function setSessionCookie(res, token) {
  res.setHeader("Set-Cookie", `ossper_session=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000`);
}

function clearSessionCookie(res) {
  res.setHeader("Set-Cookie", "ossper_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0");
}

function setStateCookie(res, state) {
  res.setHeader("Set-Cookie", `ossper_oauth_state=${state}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`);
}

function clearStateCookie(res) {
  res.append("Set-Cookie", "ossper_oauth_state=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0");
}

async function sessionAccountId(req) {
  const token = cookieValue(req, "ossper_session");
  if (!token) return null;
  const hash = hashToken(token);
  const q = await pool.query(`
    SELECT account_id FROM sessions WHERE token_hash=$1 AND expires_at > NOW()
  `, [hash]);
  if (!q.rows.length) return null;
  await pool.query("UPDATE sessions SET last_seen_at=NOW() WHERE token_hash=$1", [hash]);
  return q.rows[0].account_id;
}

async function requestAccountId(req) {
  const sessionId = await sessionAccountId(req);
  if (sessionId) return sessionId;
  const guestId = req.header("x-account-id");
  if (guestId && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(guestId)) return guestId;
  return null;
}

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS matches (
      id SERIAL PRIMARY KEY,
      event_name TEXT NOT NULL DEFAULT 'Ossper Weekly',
      event_day TEXT NOT NULL,
      format TEXT NOT NULL,
      side_a_name TEXT NOT NULL,
      side_b_name TEXT NOT NULL,
      scheduled_at TIMESTAMPTZ,
      status TEXT NOT NULL DEFAULT 'DRAFT',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CHECK (event_day IN ('FRIDAY','SATURDAY','SUNDAY')),
      CHECK (format IN ('1v1','2v2')),
      CHECK (status IN ('DRAFT','SCHEDULED','LIVE','COMPLETE','CANCELLED'))
    );

    CREATE TABLE IF NOT EXISTS markets (
      id SERIAL PRIMARY KEY,
      match_id INTEGER REFERENCES matches(id) ON DELETE SET NULL,
      question TEXT NOT NULL,
      description TEXT NOT NULL DEFAULT '',
      yes_price NUMERIC(10,4) NOT NULL DEFAULT 0.50,
      opening_yes_price NUMERIC(10,4) NOT NULL DEFAULT 0.50,
      liquidity NUMERIC(18,4) NOT NULL DEFAULT 100.00,
      status TEXT NOT NULL DEFAULT 'DRAFT',
      close_at TIMESTAMPTZ,
      result TEXT,
      market_type TEXT NOT NULL DEFAULT 'BINARY',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CHECK (yes_price >= 0.01 AND yes_price <= 0.99),
      CHECK (status IN ('DRAFT','OPEN','TRADING','CLOSED','AWAITING_RESULT','RESOLVED','SETTLED','VOID')),
      CHECK (market_type IN ('BINARY','MULTI'))
    );

    CREATE TABLE IF NOT EXISTS accounts (
      id UUID PRIMARY KEY,
      balance NUMERIC(18,4) NOT NULL DEFAULT 500.00,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS sessions (
      id UUID PRIMARY KEY,
      account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
      token_hash TEXT NOT NULL UNIQUE,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS sessions_account_idx ON sessions(account_id);
    CREATE INDEX IF NOT EXISTS sessions_expiry_idx ON sessions(expires_at);

    CREATE TABLE IF NOT EXISTS positions (
      account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
      market_id INTEGER NOT NULL REFERENCES markets(id) ON DELETE CASCADE,
      side TEXT NOT NULL,
      quantity INTEGER NOT NULL DEFAULT 0,
      avg_cost NUMERIC(18,6) NOT NULL DEFAULT 0,
      realized_pnl NUMERIC(18,4) NOT NULL DEFAULT 0,
      PRIMARY KEY (account_id, market_id, side),
      CHECK (side IN ('YES','NO')),
      CHECK (quantity >= 0)
    );

    CREATE TABLE IF NOT EXISTS trades (
      id BIGSERIAL PRIMARY KEY,
      account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
      market_id INTEGER NOT NULL REFERENCES markets(id) ON DELETE CASCADE,
      side TEXT NOT NULL,
      action TEXT NOT NULL,
      quantity INTEGER NOT NULL,
      price NUMERIC(10,4) NOT NULL,
      gross NUMERIC(18,4) NOT NULL,
      fee NUMERIC(18,4) NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CHECK (side IN ('YES','NO')),
      CHECK (action IN ('BUY','SELL'))
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      id BIGSERIAL PRIMARY KEY,
      actor TEXT NOT NULL,
      action TEXT NOT NULL,
      market_id INTEGER,
      details JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS market_outcomes (
      id BIGSERIAL PRIMARY KEY,
      market_id INTEGER NOT NULL REFERENCES markets(id) ON DELETE CASCADE,
      outcome_key TEXT NOT NULL,
      label TEXT NOT NULL,
      price NUMERIC(10,6) NOT NULL,
      opening_price NUMERIC(10,6) NOT NULL,
      sort_order INTEGER NOT NULL DEFAULT 0,
      UNIQUE (market_id, outcome_key)
    );
    CREATE INDEX IF NOT EXISTS market_outcomes_market_idx ON market_outcomes(market_id, sort_order);

    CREATE TABLE IF NOT EXISTS notifications (
      id BIGSERIAL PRIMARY KEY,
      account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
      type TEXT NOT NULL,
      title TEXT NOT NULL,
      message TEXT NOT NULL,
      market_id INTEGER REFERENCES markets(id) ON DELETE SET NULL,
      read_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS notifications_account_idx ON notifications(account_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS notifications_unread_idx ON notifications(account_id, read_at);

    CREATE TABLE IF NOT EXISTS ledger_entries (
      id BIGSERIAL PRIMARY KEY,
      account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
      entry_type TEXT NOT NULL,
      amount NUMERIC(18,4) NOT NULL,
      balance_before NUMERIC(18,4) NOT NULL,
      balance_after NUMERIC(18,4) NOT NULL,
      market_id INTEGER REFERENCES markets(id) ON DELETE SET NULL,
      trade_id BIGINT REFERENCES trades(id) ON DELETE SET NULL,
      reference TEXT,
      details JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS system_controls (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      frozen BOOLEAN NOT NULL DEFAULT FALSE,
      reason TEXT NOT NULL DEFAULT '',
      changed_by TEXT NOT NULL DEFAULT 'system',
      changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    INSERT INTO system_controls (id, frozen) VALUES (1, FALSE) ON CONFLICT (id) DO NOTHING;

    CREATE TABLE IF NOT EXISTS admin_roles (
      id BIGSERIAL PRIMARY KEY,
      discord_id TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'admin',
      granted_by TEXT NOT NULL DEFAULT 'system',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      revoked_at TIMESTAMPTZ,
      CHECK (role IN ('owner','admin'))
    );
    CREATE INDEX IF NOT EXISTS admin_roles_discord_idx ON admin_roles(discord_id);
    CREATE UNIQUE INDEX IF NOT EXISTS admin_roles_active_discord_idx ON admin_roles(discord_id) WHERE revoked_at IS NULL;
  `);
  await pool.query("DELETE FROM sessions WHERE expires_at <= NOW()");

  // Additive migrations for existing Ossper databases. No data wipe.
  await pool.query(`ALTER TABLE markets ADD COLUMN IF NOT EXISTS market_type TEXT NOT NULL DEFAULT 'BINARY'`);
  await pool.query(`ALTER TABLE markets DROP CONSTRAINT IF EXISTS markets_result_check`);
  await pool.query(`ALTER TABLE matches DROP CONSTRAINT IF EXISTS matches_format_check`);
  await pool.query(`ALTER TABLE matches ADD CONSTRAINT matches_format_check CHECK (format IN ('1v1','2v2','PICK_EM'))`);
  await pool.query(`ALTER TABLE positions DROP CONSTRAINT IF EXISTS positions_side_check`);
  await pool.query(`ALTER TABLE trades DROP CONSTRAINT IF EXISTS trades_side_check`);
  await pool.query(`UPDATE markets SET market_type='BINARY' WHERE market_type IS NULL OR market_type=''`);

  // Safe migrations for databases created by v0.6.1.
  await pool.query(`ALTER TABLE markets ADD COLUMN IF NOT EXISTS match_id INTEGER REFERENCES matches(id) ON DELETE SET NULL`);
  await pool.query(`ALTER TABLE markets ADD COLUMN IF NOT EXISTS opening_yes_price NUMERIC(10,4) NOT NULL DEFAULT 0.50`);
  await pool.query(`ALTER TABLE markets ADD COLUMN IF NOT EXISTS liquidity NUMERIC(18,4) NOT NULL DEFAULT 100.00`);
  await pool.query(`ALTER TABLE accounts ADD COLUMN IF NOT EXISTS discord_id TEXT`);
  await pool.query(`ALTER TABLE accounts ADD COLUMN IF NOT EXISTS display_name TEXT`);
  await pool.query(`ALTER TABLE accounts ADD COLUMN IF NOT EXISTS avatar_url TEXT`);
  await pool.query(`ALTER TABLE accounts ADD COLUMN IF NOT EXISTS auth_provider TEXT NOT NULL DEFAULT 'guest'`);
  await pool.query(`ALTER TABLE accounts ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ`);
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS accounts_discord_id_idx ON accounts(discord_id) WHERE discord_id IS NOT NULL`);
  await pool.query(`UPDATE markets SET opening_yes_price=yes_price WHERE opening_yes_price IS NULL OR opening_yes_price=0`);
  await pool.query(`UPDATE markets SET liquidity=100.00 WHERE liquidity IS NULL OR liquidity<=0`);

  const { rows } = await pool.query("SELECT id FROM markets ORDER BY id LIMIT 1");
  if (!rows.length) {
    await pool.query(`
      INSERT INTO markets (question, description, yes_price, status)
      VALUES ($1, $2, 0.50, 'TRADING')
    `, [
      "Will Player A win Friday 1v1?",
      "Demo market — virtual money only. This is the initial Ossper test market."
    ]);
  }
}

async function getAccount(accountId) {
  const result = await pool.query("SELECT * FROM accounts WHERE id = $1", [accountId]);
  return result.rows[0] || null;
}

async function ensureAccount(accountId) {
  await pool.query(
    "INSERT INTO accounts (id, balance) VALUES ($1, 500.00) ON CONFLICT (id) DO NOTHING",
    [accountId]
  );
}

async function getSystemControl() {
  const q = await pool.query("SELECT * FROM system_controls WHERE id=1");
  return q.rows[0] || { frozen: false, reason: '', changed_by: 'system', changed_at: null };
}

async function assertSystemActive() {
  const control = await getSystemControl();
  if (control.frozen) throw new Error(`Ossper is frozen by administration${control.reason ? `: ${control.reason}` : '.'}`);
  return control;
}

async function addLedgerEntry(client, { accountId, entryType, amount, balanceBefore, balanceAfter, marketId = null, tradeId = null, reference = null, details = {} }) {
  await client.query(`
    INSERT INTO ledger_entries (account_id, entry_type, amount, balance_before, balance_after, market_id, trade_id, reference, details)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
  `, [accountId, entryType, amount, balanceBefore, balanceAfter, marketId, tradeId, reference, JSON.stringify(details)]);
}

async function addNotification(client, { accountId, type, title, message, marketId = null }) {
  await client.query(`
    INSERT INTO notifications (account_id, type, title, message, market_id)
    VALUES ($1,$2,$3,$4,$5)
  `, [accountId, type, title, message, marketId]);
}

async function notifyPositionHolders(client, marketId, type, title, message) {
  const q = await client.query(`SELECT DISTINCT account_id FROM positions WHERE market_id=$1 AND quantity > 0`, [marketId]);
  for (const row of q.rows) await addNotification(client, { accountId: row.account_id, type, title, message, marketId });
}

async function marketSnapshot(marketId, accountId) {
  await ensureAccount(accountId);
  const marketQ = await pool.query(`
    SELECT m.*,
      mt.event_name, mt.event_day, mt.format, mt.side_a_name, mt.side_b_name,
      mt.scheduled_at, mt.status AS match_status
    FROM markets m
    LEFT JOIN matches mt ON mt.id = m.match_id
    WHERE m.id=$1
  `, [marketId]);
  if (!marketQ.rows.length) return null;
  const market = marketQ.rows[0];
  const positionsQ = await pool.query(
    "SELECT side, quantity, avg_cost, realized_pnl FROM positions WHERE account_id=$1 AND market_id=$2 AND quantity > 0 ORDER BY side",
    [accountId, marketId]
  );
  const tradesQ = await pool.query(
    "SELECT action, side, quantity, price, gross, fee, created_at FROM trades WHERE account_id=$1 AND market_id=$2 ORDER BY id DESC LIMIT 30",
    [accountId, marketId]
  );
  const volumeQ = await pool.query("SELECT COALESCE(SUM(gross),0) AS volume FROM trades WHERE market_id=$1", [marketId]);
  const outcomesQ = await pool.query("SELECT outcome_key, label, price, opening_price, sort_order FROM market_outcomes WHERE market_id=$1 ORDER BY sort_order, id", [marketId]);
  const account = await getAccount(accountId);
  if (!account) return null;
  const yes = Number(market.yes_price);
  return {
    market: {
      ...market,
      yes_price: yes,
      opening_yes_price: Number(market.opening_yes_price ?? yes),
      liquidity: Number(market.liquidity ?? 100),
      no_price: Number((1 - yes).toFixed(4)),
      volume: Number(volumeQ.rows[0].volume),
      market_type: market.market_type || 'BINARY',
      outcomes: outcomesQ.rows.map(o => ({ outcome_key: o.outcome_key, label: o.label, price: Number(o.price), opening_price: Number(o.opening_price), sort_order: Number(o.sort_order) }))
    },
    account: {
      balance: Number(account.balance),
      positions: positionsQ.rows.map(p => ({ side: p.side, quantity: Number(p.quantity), avg_cost: Number(p.avg_cost), realized_pnl: Number(p.realized_pnl) })),
      trades: tradesQ.rows.map(t => ({ ...t, quantity: Number(t.quantity), price: Number(t.price), gross: Number(t.gross), fee: Number(t.fee) }))
    }
  };
}

function clampPrice(p) {
  return Math.max(0.01, Math.min(0.99, Number(p.toFixed(4))));
}

function sigmoid(x) {
  if (x > 40) return 1;
  if (x < -40) return 0;
  return 1 / (1 + Math.exp(-x));
}

function logit(p) {
  const q = Math.max(0.0001, Math.min(0.9999, p));
  return Math.log(q / (1 - q));
}

// Liquidity is an approximate market-depth control in virtual dollars.
// Larger liquidity means a given trade produces less probability movement.
function projectPrice(yesPrice, liquidity, side, action, quantity) {
  const yes = Number(yesPrice);
  const liq = Math.max(1, Number(liquidity) || 100);
  const qty = Math.max(0, Number(quantity));
  const currentSidePrice = side === "YES" ? yes : 1 - yes;
  const notional = currentSidePrice * qty;
  const direction = (action === "BUY" ? 1 : -1) * (side === "YES" ? 1 : -1);
  const shift = Math.min(3, notional / liq);
  return clampPrice(sigmoid(logit(yes) + direction * shift));
}

function quoteForMarket(market, side, action, quantity) {
  const yes = Number(market.yes_price);
  const endYes = projectPrice(yes, market.liquidity, side, action, quantity);
  const startPrice = side === "YES" ? yes : 1 - yes;
  const endPrice = side === "YES" ? endYes : 1 - endYes;
  const avgPrice = (startPrice + endPrice) / 2;
  const gross = avgPrice * Number(quantity);
  const fee = gross * 0.01;
  return {
    startPrice: Number(startPrice.toFixed(4)),
    endPrice: Number(endPrice.toFixed(4)),
    averagePrice: Number(avgPrice.toFixed(4)),
    gross: Number(gross.toFixed(4)),
    fee: Number(fee.toFixed(4)),
    total: Number((gross + fee).toFixed(4)),
    priceMove: Number((endYes - yes).toFixed(4)),
    yesPriceAfter: endYes,
    noPriceAfter: Number((1 - endYes).toFixed(4)),
  };
}

function normalizeOutcomeKey(label, index) {
  const base = String(label || `Option ${index + 1}`).trim().toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40) || `option-${index+1}`;
  return `${base}-${index+1}`;
}

function projectMultiPrices(outcomes, selectedKey, action, quantity, liquidity) {
  const rows = outcomes.map(o => ({ ...o, price: Number(o.price) }));
  const selected = rows.find(o => o.outcome_key === selectedKey);
  if (!selected) throw new Error('Outcome not found.');
  const liq = Math.max(1, Number(liquidity) || 100);
  const qty = Math.max(0, Number(quantity));
  const direction = action === 'BUY' ? 1 : -1;
  const notional = selected.price * qty;
  const shift = Math.min(2.5, notional / liq);
  const oldP = selected.price;
  const rawNew = clampPrice(sigmoid(logit(oldP) + direction * shift));
  const remainingOld = Math.max(0.0001, 1 - oldP);
  const remainingNew = Math.max(0.0001, 1 - rawNew);
  for (const o of rows) {
    if (o.outcome_key === selectedKey) o.nextPrice = rawNew;
    else o.nextPrice = Number((o.price * remainingNew / remainingOld).toFixed(6));
  }
  const sumOther = rows.filter(o=>o.outcome_key!==selectedKey).reduce((a,o)=>a+o.nextPrice,0);
  const diff = 1 - rawNew - sumOther;
  if (rows.length > 1) {
    const others = rows.filter(o=>o.outcome_key!==selectedKey);
    const target = others[others.length-1];
    target.nextPrice = Number((target.nextPrice + diff).toFixed(6));
  }
  return { rows, startPrice: oldP, endPrice: rawNew, averagePrice: (oldP + rawNew) / 2 };
}

function quoteForMulti(outcomes, liquidity, side, action, quantity) {
  const projected = projectMultiPrices(outcomes, side, action, quantity, liquidity);
  const gross = projected.averagePrice * Number(quantity);
  const fee = gross * 0.01;
  return {
    startPrice: Number(projected.startPrice.toFixed(4)),
    endPrice: Number(projected.endPrice.toFixed(4)),
    averagePrice: Number(projected.averagePrice.toFixed(4)),
    gross: Number(gross.toFixed(4)),
    fee: Number(fee.toFixed(4)),
    total: Number((gross + fee).toFixed(4)),
    priceMove: Number((projected.endPrice - projected.startPrice).toFixed(4)),
    outcomePricesAfter: projected.rows.map(o => ({ outcome_key:o.outcome_key, price:Number(o.nextPrice.toFixed(6)) }))
  };
}

async function executeTrade({ accountId, marketId, action, side, quantity }) {
  quantity = Math.floor(Number(quantity));
  if (!Number.isInteger(quantity) || quantity <= 0 || quantity > 10000) throw new Error("Quantity must be a whole number from 1 to 10,000.");
  side = String(side || '').toUpperCase();
  action = String(action || '').toUpperCase();
  if (!side || !["BUY","SELL"].includes(action)) throw new Error("Invalid trade.");

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const controlQ = await client.query("SELECT frozen, reason FROM system_controls WHERE id=1 FOR UPDATE");
    if (controlQ.rows[0]?.frozen) throw new Error(`Ossper is frozen by administration${controlQ.rows[0].reason ? `: ${controlQ.rows[0].reason}` : '.'}`);
    const m = await client.query("SELECT * FROM markets WHERE id=$1 FOR UPDATE", [marketId]);
    if (!m.rows.length) throw new Error("Market not found.");
    const market = m.rows[0];
    if (!['OPEN','TRADING'].includes(market.status)) throw new Error("Trading is closed for this market.");
    if (market.close_at && new Date(market.close_at).getTime() <= Date.now()) {
      await client.query("UPDATE markets SET status='CLOSED', updated_at=NOW() WHERE id=$1", [marketId]);
      throw new Error("Trading has closed for this market.");
    }
    if (market.market_type !== 'MULTI' && !['YES','NO'].includes(side)) throw new Error('Invalid binary market side.');
    if (market.market_type === 'MULTI') {
      const oq = await client.query("SELECT * FROM market_outcomes WHERE market_id=$1 ORDER BY sort_order,id FOR UPDATE", [marketId]);
      if (!oq.rows.some(o=>o.outcome_key===side)) throw new Error('Outcome not found.');
    }

    const accountQ = await client.query("SELECT * FROM accounts WHERE id=$1 FOR UPDATE", [accountId]);
    if (!accountQ.rows.length) throw new Error("Account not found.");
    const account = accountQ.rows[0];

    let quote;
    if (market.market_type === 'MULTI') {
      const oq = await client.query("SELECT outcome_key, label, price FROM market_outcomes WHERE market_id=$1 ORDER BY sort_order,id", [marketId]);
      quote = quoteForMulti(oq.rows, market.liquidity, side, action, quantity);
    } else {
      quote = quoteForMarket(market, side, action, quantity);
    }
    const price = quote.averagePrice;
    const gross = quote.gross;
    const fee = quote.fee;

    const posQ = await client.query("SELECT * FROM positions WHERE account_id=$1 AND market_id=$2 AND side=$3 FOR UPDATE", [accountId, marketId, side]);
    const current = posQ.rows[0] || { quantity: 0, avg_cost: 0, realized_pnl: 0 };
    const currentQty = Number(current.quantity);
    const currentAvg = Number(current.avg_cost);

    if (action === "BUY") {
      const totalDebit = Number((gross + fee).toFixed(4));
      if (Number(account.balance) + 1e-9 < totalDebit) throw new Error("Insufficient balance.");
      const newQty = currentQty + quantity;
      const newAvg = ((currentQty * currentAvg) + gross) / newQty;
      const balanceBefore = Number(account.balance);
      const balanceAfter = Number((balanceBefore - totalDebit).toFixed(4));
      await client.query("UPDATE accounts SET balance = $1 WHERE id=$2", [balanceAfter, accountId]);
      await client.query(`INSERT INTO positions (account_id, market_id, side, quantity, avg_cost) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (account_id, market_id, side) DO UPDATE SET quantity=EXCLUDED.quantity, avg_cost=EXCLUDED.avg_cost`, [accountId, marketId, side, newQty, newAvg]);
    } else {
      if (currentQty < quantity) throw new Error(`You only own ${currentQty} ${side} contracts.`);
      const netCredit = Number((gross - fee).toFixed(4));
      const newQty = currentQty - quantity;
      const realized = Number((gross - (currentAvg * quantity) - fee).toFixed(4));
      const balanceBefore = Number(account.balance);
      const balanceAfter = Number((balanceBefore + netCredit).toFixed(4));
      await client.query("UPDATE accounts SET balance = $1 WHERE id=$2", [balanceAfter, accountId]);
      await client.query(`INSERT INTO positions (account_id, market_id, side, quantity, avg_cost, realized_pnl) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (account_id, market_id, side) DO UPDATE SET quantity=EXCLUDED.quantity, avg_cost=EXCLUDED.avg_cost, realized_pnl=positions.realized_pnl + EXCLUDED.realized_pnl`, [accountId, marketId, side, newQty, newQty ? currentAvg : 0, realized]);
    }

    if (market.market_type === 'MULTI') {
      for (const o of quote.outcomePricesAfter) await client.query("UPDATE market_outcomes SET price=$1 WHERE market_id=$2 AND outcome_key=$3", [o.price, marketId, o.outcome_key]);
    } else {
      await client.query("UPDATE markets SET yes_price=$1, updated_at=NOW() WHERE id=$2", [quote.yesPriceAfter, marketId]);
    }
    await client.query("UPDATE markets SET updated_at=NOW() WHERE id=$1", [marketId]);

    const tradeQ = await client.query(`INSERT INTO trades (account_id, market_id, side, action, quantity, price, gross, fee) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`, [accountId, marketId, side, action, quantity, price, gross, fee]);
    const ledgerAmount = action === 'BUY' ? -Number((gross + fee).toFixed(4)) : Number((gross - fee).toFixed(4));
    const balanceBeforeForLedger = Number(account.balance);
    const balanceAfterForLedger = Number((balanceBeforeForLedger + ledgerAmount).toFixed(4));
    await addLedgerEntry(client, { accountId, entryType: action === 'BUY' ? 'TRADE_DEBIT' : 'TRADE_CREDIT', amount: ledgerAmount, balanceBefore: balanceBeforeForLedger, balanceAfter: balanceAfterForLedger, marketId, tradeId: tradeQ.rows[0].id, reference: `${action}_${side}`, details: { side, quantity, price, gross, fee } });
    await client.query(`INSERT INTO audit_logs (actor, action, market_id, details) VALUES ($1,$2,$3,$4)`, [accountId, `${action}_${side}`, marketId, JSON.stringify({ quantity, price, gross, fee, priceMove: quote.priceMove, marketType: market.market_type })]);
    await client.query("COMMIT");
    return await marketSnapshot(marketId, accountId);
  } catch (e) { await client.query("ROLLBACK"); throw e; }
  finally { client.release(); }
}

app.get("/api/health", async (_req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true, database: true, service: "ossper-markets" });
  } catch {
    res.status(503).json({ ok: false, database: false });
  }
});

app.get("/api/auth/config", (_req, res) => {
  res.json({ discordEnabled: DISCORD_AUTH_ENABLED });
});

app.get("/api/me", async (req, res) => {
  // Authentication status must come only from a valid server-side session.
  // The x-account-id header is intentionally NOT sufficient to authenticate.
  const accountId = await sessionAccountId(req);
  if (!accountId) return res.json({ authenticated: false, account: null });
  const q = await pool.query("SELECT id, display_name, avatar_url, auth_provider, discord_id FROM accounts WHERE id=$1", [accountId]);
  if (!q.rows.length) return res.json({ authenticated: false, account: null });
  const a = q.rows[0];
  res.json({ authenticated: true, account: { id: a.id, displayName: a.display_name || 'Discord user', avatarUrl: a.avatar_url || null, provider: a.auth_provider, discordLinked: Boolean(a.discord_id) } });
});

app.post("/api/session", async (_req, res) => {
  const id = crypto.randomUUID();
  await ensureAccount(id);
  res.json({ accountId: id, guest: true });
});

app.post("/api/auth/discord/start", async (req, res) => {
  if (!DISCORD_AUTH_ENABLED) return res.status(503).json({ error: "Discord login is not configured yet." });
  const guestId = req.header("x-account-id");
  const accountId = guestId && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(guestId) ? guestId : null;
  const state = makeAuthState(accountId, "/#markets");
  setStateCookie(res, state);
  const params = new URLSearchParams({
    client_id: DISCORD_CLIENT_ID,
    response_type: "code",
    redirect_uri: DISCORD_REDIRECT_URI,
    scope: "identify",
    state
  });
  res.json({ url: `https://discord.com/oauth2/authorize?${params.toString()}` });
});

app.get("/auth/discord", async (req, res) => {
  if (!DISCORD_AUTH_ENABLED) return res.status(503).send("Discord login is not configured yet.");
  const state = makeAuthState(null, "/#markets");
  setStateCookie(res, state);
  const params = new URLSearchParams({ client_id: DISCORD_CLIENT_ID, response_type: "code", redirect_uri: DISCORD_REDIRECT_URI, scope: "identify", state });
  res.redirect(`https://discord.com/oauth2/authorize?${params.toString()}`);
});

app.get("/auth/discord/admin", async (req, res) => {
  if (!DISCORD_AUTH_ENABLED) return res.status(503).send("Discord login is not configured yet.");
  const accountId = await sessionAccountId(req);
  const state = makeAuthState(accountId, "/admin");
  setStateCookie(res, state);
  const params = new URLSearchParams({ client_id: DISCORD_CLIENT_ID, response_type: "code", redirect_uri: DISCORD_REDIRECT_URI, scope: "identify", state });
  res.redirect(`https://discord.com/oauth2/authorize?${params.toString()}`);
});

app.get("/api/admin/discord/start", async (req, res) => {
  if (!DISCORD_AUTH_ENABLED) return res.status(503).json({ error: "Discord login is not configured yet." });
  const accountId = await sessionAccountId(req);
  const state = makeAuthState(accountId, "/admin");
  setStateCookie(res, state);
  const params = new URLSearchParams({ client_id: DISCORD_CLIENT_ID, response_type: "code", redirect_uri: DISCORD_REDIRECT_URI, scope: "identify", state });
  res.json({ url: `https://discord.com/oauth2/authorize?${params.toString()}` });
});

app.get("/auth/discord/callback", async (req, res) => {
  if (!DISCORD_AUTH_ENABLED) return res.status(503).send("Discord login is not configured yet.");
  const state = readAuthState(req.query.state);
  const cookieState = readAuthState(cookieValue(req, "ossper_oauth_state"));
  if (!state || !cookieState || state.nonce !== cookieState.nonce) return res.status(400).send("Discord login state expired or invalid. Please try again.");
  clearStateCookie(res);
  const code = String(req.query.code || "");
  if (!code) return res.status(400).send("Discord did not return an authorization code.");
  try {
    const tokenResp = await fetch("https://discord.com/api/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ client_id: DISCORD_CLIENT_ID, client_secret: DISCORD_CLIENT_SECRET, grant_type: "authorization_code", code, redirect_uri: DISCORD_REDIRECT_URI })
    });
    const tokenData = await tokenResp.json();
    if (!tokenResp.ok || !tokenData.access_token) throw new Error("Discord token exchange failed.");
    const userResp = await fetch("https://discord.com/api/users/@me", { headers: { Authorization: `Bearer ${tokenData.access_token}` } });
    const user = await userResp.json();
    if (!userResp.ok || !user.id) throw new Error("Discord identity lookup failed.");

    const discordId = String(user.id);
    const displayName = String(user.global_name || user.username || "Discord user").slice(0, 120);
    const avatarUrl = user.avatar ? `https://cdn.discordapp.com/avatars/${discordId}/${user.avatar}.png?size=128` : null;
    const client = await pool.connect();
    let accountId;
    try {
      await client.query("BEGIN");
      const linked = await client.query("SELECT id FROM accounts WHERE discord_id=$1 FOR UPDATE", [discordId]);
      if (linked.rows.length) {
        accountId = linked.rows[0].id;
      } else if (cookieState.accountId) {
        const guest = await client.query("SELECT id, auth_provider, discord_id FROM accounts WHERE id=$1 FOR UPDATE", [cookieState.accountId]);
        if (guest.rows.length && !guest.rows[0].discord_id) {
          accountId = guest.rows[0].id;
          await client.query("UPDATE accounts SET discord_id=$1, display_name=$2, avatar_url=$3, auth_provider='discord', last_login_at=NOW() WHERE id=$4", [discordId, displayName, avatarUrl, accountId]);
        }
      }
      if (!accountId) {
        accountId = crypto.randomUUID();
        await client.query("INSERT INTO accounts (id, balance, discord_id, display_name, avatar_url, auth_provider, last_login_at) VALUES ($1,500.00,$2,$3,$4,'discord',NOW())", [accountId, discordId, displayName, avatarUrl]);
      } else {
        await client.query("UPDATE accounts SET display_name=$1, avatar_url=$2, auth_provider='discord', last_login_at=NOW() WHERE id=$3", [displayName, avatarUrl, accountId]);
      }
      const rawToken = crypto.randomBytes(32).toString("base64url");
      const tokenHash = hashToken(rawToken);
      await client.query("DELETE FROM sessions WHERE expires_at <= NOW() OR account_id=$1", [accountId]);
      await client.query("INSERT INTO sessions (id, account_id, token_hash, expires_at) VALUES ($1,$2,$3,NOW()+INTERVAL '30 days')", [crypto.randomUUID(), accountId, tokenHash]);
      await client.query("INSERT INTO audit_logs (actor, action, details) VALUES ($1,'DISCORD_LOGIN',$2)", [accountId, JSON.stringify({ discordId, displayName })]);
      await client.query("COMMIT");
      setSessionCookie(res, rawToken);
      res.redirect(cookieState.returnTo === "/admin" ? "/admin" : "/#markets");
    } catch (e) {
      await client.query("ROLLBACK");
      throw e;
    } finally { client.release(); }
  } catch (e) {
    res.status(400).send(`Discord login failed: ${e.message}`);
  }
});

app.post("/api/logout", async (req, res) => {
  const token = cookieValue(req, "ossper_session");
  if (token) await pool.query("DELETE FROM sessions WHERE token_hash=$1", [hashToken(token)]);
  clearSessionCookie(res);
  res.json({ ok: true });
});

async function closeExpiredMarkets() {
  const control = await getSystemControl();
  if (control.frozen) return;
  const q = await pool.query(`
    UPDATE markets
    SET status='CLOSED', updated_at=NOW()
    WHERE status IN ('OPEN','TRADING')
      AND close_at IS NOT NULL
      AND close_at <= NOW()
    RETURNING id, match_id
  `);
  for (const row of q.rows) {
    if (row.match_id) await pool.query("UPDATE matches SET status='LIVE', updated_at=NOW() WHERE id=$1", [row.match_id]);
    const client=await pool.connect();
    try { await client.query('BEGIN'); await notifyPositionHolders(client,row.id,'MARKET_STATUS','Trading closed','Trading has closed automatically. Your open position remains active until the market is resolved and settled.'); await client.query('COMMIT'); } catch(e){ await client.query('ROLLBACK'); } finally { client.release(); }
  }
}

app.get("/api/markets", async (req, res) => {
  const accountId = await requestAccountId(req);
  if (!accountId) return res.status(400).json({ error: "Missing account." });
  await ensureAccount(accountId);
  await closeExpiredMarkets();
  const q = await pool.query("SELECT * FROM markets WHERE status <> 'DRAFT' ORDER BY id DESC");
  const out = [];
  for (const m of q.rows) {
    const snap = await marketSnapshot(m.id, accountId);
    out.push(snap);
  }
  res.json(out);
});

app.get("/api/market/:id", async (req, res) => {
  const accountId = await requestAccountId(req);
  if (!accountId) return res.status(400).json({ error: "Missing account." });
  await ensureAccount(accountId);
  const snap = await marketSnapshot(Number(req.params.id), accountId);
  if (!snap) return res.status(404).json({ error: "Market not found." });
  res.json(snap);
});

app.post("/api/quote", async (req, res) => {
  try {
    await assertSystemActive();
    const marketId = Number(req.body?.marketId);
    const side = String(req.body?.side || "").toUpperCase();
    const action = String(req.body?.action || "BUY").toUpperCase();
    const quantity = Math.floor(Number(req.body?.quantity));
    if (!Number.isInteger(quantity) || quantity <= 0 || quantity > 10000) throw new Error("Quantity must be a whole number from 1 to 10,000.");
    if (!side || !["BUY","SELL"].includes(action)) throw new Error("Invalid quote.");
    const q = await pool.query("SELECT * FROM markets WHERE id=$1", [marketId]);
    if (!q.rows.length) return res.status(404).json({ error: "Market not found." });
    const market = q.rows[0];
    if (!["OPEN","TRADING"].includes(market.status)) throw new Error("Trading is closed for this market.");
    if (market.market_type === 'MULTI') {
      const oq = await pool.query("SELECT outcome_key, label, price FROM market_outcomes WHERE market_id=$1 ORDER BY sort_order,id", [marketId]);
      if (!oq.rows.some(o=>o.outcome_key===side)) throw new Error('Outcome not found.');
      return res.json(quoteForMulti(oq.rows, market.liquidity, side, action, quantity));
    }
    if (!["YES","NO"].includes(side)) throw new Error("Invalid binary market side.");
    res.json(quoteForMarket(market, side, action, quantity));
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.post("/api/trade", async (req, res) => {
  try {
    await assertSystemActive();
    const accountId = await requestAccountId(req);
    if (!accountId) return res.status(400).json({ error: "Missing account." });
    await ensureAccount(accountId);
    const snap = await executeTrade({
      accountId,
      marketId: Number(req.body.marketId),
      action: req.body.action,
      side: req.body.side,
      quantity: req.body.quantity,
    });
    res.json(snap);
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.get("/api/notifications", async (req, res) => {
  const accountId = await requestAccountId(req);
  if (!accountId) return res.status(400).json({ error: "Missing account." });
  await ensureAccount(accountId);
  const q = await pool.query(`SELECT id,type,title,message,market_id,read_at,created_at FROM notifications WHERE account_id=$1 ORDER BY id DESC LIMIT 50`, [accountId]);
  const unread = q.rows.filter(x=>!x.read_at).length;
  res.json({ notifications:q.rows, unread });
});
app.post("/api/notifications/:id/read", async (req, res) => {
  const accountId = await requestAccountId(req);
  if (!accountId) return res.status(400).json({ error: "Missing account." });
  await pool.query("UPDATE notifications SET read_at=COALESCE(read_at,NOW()) WHERE id=$1 AND account_id=$2", [Number(req.params.id), accountId]);
  res.json({ ok:true });
});
app.post("/api/notifications/read-all", async (req, res) => {
  const accountId = await requestAccountId(req);
  if (!accountId) return res.status(400).json({ error: "Missing account." });
  await pool.query("UPDATE notifications SET read_at=COALESCE(read_at,NOW()) WHERE account_id=$1 AND read_at IS NULL", [accountId]);
  res.json({ ok:true });
});

app.get("/api/system", async (_req, res) => {
  const control = await getSystemControl();
  res.json({ frozen: Boolean(control.frozen), reason: control.reason || '', changedAt: control.changed_at });
});

app.post("/api/admin/bootstrap", async (req, res) => {
  if (!ADMIN_BOOTSTRAP_ENABLED) return res.status(503).json({ error: "Admin bootstrap is unavailable." });
  const accountId = await sessionAccountId(req);
  if (!accountId) return res.status(401).json({ error: "Sign in with Discord first." });
  const supplied = String(req.body?.key || "");
  const a = Buffer.from(supplied);
  const b = Buffer.from(ADMIN_KEY);
  if (!supplied || a.length !== b.length || !crypto.timingSafeEqual(a, b)) return res.status(401).json({ error: "Invalid admin key." });

  const acct = await pool.query("SELECT discord_id FROM accounts WHERE id=$1", [accountId]);
  const discordId = acct.rows[0]?.discord_id;
  if (!discordId) return res.status(400).json({ error: "Your Ossper account is not linked to Discord." });

  const ownerQ = await pool.query("SELECT id FROM admin_roles WHERE role='owner' AND revoked_at IS NULL LIMIT 1");
  if (ownerQ.rows.length) return res.status(409).json({ error: "An Ossper owner is already configured." });

  await pool.query("INSERT INTO admin_roles (discord_id, role, granted_by) VALUES ($1,'owner','bootstrap') ON CONFLICT DO NOTHING", [discordId]);
  await pool.query("INSERT INTO audit_logs (actor, action, details) VALUES ($1,'ADMIN_BOOTSTRAP',$2)", [accountId, JSON.stringify({ discordId, role: 'owner' })]);
  res.json({ ok: true, role: "owner" });
});

app.get("/api/admin/roles", adminOnly, async (_req, res) => {
  const q = await pool.query(`
    SELECT ar.discord_id, ar.role, ar.granted_by, ar.created_at, a.display_name, a.avatar_url
    FROM admin_roles ar
    LEFT JOIN accounts a ON a.discord_id=ar.discord_id
    WHERE ar.revoked_at IS NULL
    ORDER BY CASE ar.role WHEN 'owner' THEN 1 ELSE 2 END, ar.created_at ASC
  `);
  res.json(q.rows);
});

app.post("/api/admin/roles", adminOnly, ownerOnly, async (req, res) => {
  const discordId = String(req.body?.discordId || '').trim();
  if (!/^\d{15,22}$/.test(discordId)) return res.status(400).json({ error: "Enter a valid Discord user ID." });
  const existing = await pool.query("SELECT id, role FROM admin_roles WHERE discord_id=$1 AND revoked_at IS NULL", [discordId]);
  if (existing.rows.length) return res.status(409).json({ error: "That Discord account already has an admin role." });
  const grantedBy = req.admin?.discordId || 'admin_key';
  const q = await pool.query("INSERT INTO admin_roles (discord_id, role, granted_by) VALUES ($1,'admin',$2) RETURNING *", [discordId, grantedBy]);
  await pool.query("INSERT INTO audit_logs (actor, action, details) VALUES ($1,'ADMIN_ROLE_GRANTED',$2)", [req.admin?.accountId || 'admin', JSON.stringify({ discordId, role: 'admin', grantedBy })]);
  res.json({ ok: true, role: q.rows[0] });
});

app.delete("/api/admin/roles/:discordId", adminOnly, ownerOnly, async (req, res) => {
  const discordId = String(req.params.discordId || '').trim();
  const q = await pool.query("SELECT id, role FROM admin_roles WHERE discord_id=$1 AND revoked_at IS NULL", [discordId]);
  if (!q.rows.length) return res.status(404).json({ error: "Active admin role not found." });
  if (q.rows[0].role === 'owner') return res.status(400).json({ error: "The owner role cannot be revoked here." });
  await pool.query("UPDATE admin_roles SET revoked_at=NOW() WHERE id=$1", [q.rows[0].id]);
  await pool.query("INSERT INTO audit_logs (actor, action, details) VALUES ($1,'ADMIN_ROLE_REVOKED',$2)", [req.admin?.accountId || 'admin', JSON.stringify({ discordId })]);
  res.json({ ok: true });
});

app.post("/api/admin/login", (req, res) => {
  const supplied = String(req.body?.key || "");
  const a = Buffer.from(supplied);
  const b = Buffer.from(ADMIN_KEY);
  if (!supplied || a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(401).json({ error: "Invalid admin key." });
  }
  const token = makeToken({ role: "admin", exp: Date.now() + 8 * 60 * 60 * 1000 });
  setAdminCookie(res, token);
  res.json({ ok: true });
});

app.get("/api/admin/me", adminOnly, (req, res) => res.json({ ok: true, role: req.admin?.role || "admin", source: req.admin?.source || "admin_key", discordId: req.admin?.discordId || null }));

app.get("/api/admin/system", adminOnly, async (_req, res) => {
  const control = await getSystemControl();
  res.json({ frozen: Boolean(control.frozen), reason: control.reason || '', changedBy: control.changed_by, changedAt: control.changed_at });
});

app.post("/api/admin/system/freeze", adminOnly, async (req, res) => {
  const frozen = Boolean(req.body?.frozen);
  const reason = String(req.body?.reason || '').trim().slice(0, 500);
  const actor = 'admin';
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const currentQ = await client.query("SELECT * FROM system_controls WHERE id=1 FOR UPDATE");
    const previous = currentQ.rows[0] || { frozen: false, reason: '' };
    await client.query("UPDATE system_controls SET frozen=$1, reason=$2, changed_by=$3, changed_at=NOW() WHERE id=1", [frozen, reason, actor]);
    await client.query(`INSERT INTO audit_logs (actor, action, details) VALUES ($1,$2,$3)`, [actor, frozen ? 'GLOBAL_FREEZE_ENABLED' : 'GLOBAL_FREEZE_DISABLED', JSON.stringify({ reason, previousFrozen: Boolean(previous.frozen), previousReason: previous.reason || '' })]);
    await client.query('COMMIT');
    res.json({ ok: true, frozen, reason });
  } catch (e) {
    await client.query('ROLLBACK');
    res.status(400).json({ error: e.message });
  } finally {
    client.release();
  }
});



app.get("/api/admin/markets", adminOnly, async (_req, res) => {
  await closeExpiredMarkets();
  const q = await pool.query(`
    SELECT m.*,
      mt.event_name, mt.event_day, mt.format, mt.side_a_name, mt.side_b_name,
      mt.scheduled_at, mt.status AS match_status,
      COALESCE((SELECT SUM(gross) FROM trades t WHERE t.market_id=m.id),0) AS volume,
      COALESCE((SELECT COUNT(*) FROM trades t WHERE t.market_id=m.id),0) AS trade_count
    FROM markets m
    LEFT JOIN matches mt ON mt.id=m.match_id
    ORDER BY m.id DESC
  `);
  res.json(q.rows);
});

app.post("/api/admin/matches", adminOnly, async (req, res) => {
  try { await assertSystemActive(); } catch (e) { return res.status(423).json({ error: e.message }); }
  const { eventName="Ossper Weekly", eventDay, format, sideA, sideB, scheduledAt=null, closeAt=null, yesPrice=0.50, liquidity=100, outcomes=[] } = req.body || {};
  const day=String(eventDay||'').toUpperCase(), fmt=String(format||'').toUpperCase();
  const event=String(eventName||'Ossper Weekly').trim(), a=String(sideA||'').trim(), b=String(sideB||'').trim();
  const price=Number(yesPrice), depth=Number(liquidity);
  if(!['FRIDAY','SATURDAY','SUNDAY'].includes(day)) return res.status(400).json({error:'Event day must be Friday, Saturday, or Sunday.'});
  if(!['1V1','2V2','PICK_EM'].includes(fmt)) return res.status(400).json({error:'Format must be 1v1, 2v2, or Pick em.'});
  if(event.length<2) return res.status(400).json({error:'Event name is required.'});
  if(!Number.isFinite(depth)||depth<10||depth>1000000) return res.status(400).json({error:'Liquidity must be between $10 and $1,000,000.'});
  const isMulti=fmt==='PICK_EM';
  let names=[];
  if(isMulti){
    names=(Array.isArray(outcomes)?outcomes:[]).map(x=>String(x).trim()).filter(Boolean).slice(0,20);
    if(names.length<3) return res.status(400).json({error:'Pick em markets need at least 3 outcomes.'});
    if(new Set(names.map(x=>x.toLowerCase())).size!==names.length) return res.status(400).json({error:'Outcome names must be unique.'});
  } else {
    if(a.length<2||b.length<2) return res.status(400).json({error:'Both players/teams are required.'});
    if(!Number.isFinite(price)||price<0.01||price>0.99) return res.status(400).json({error:'YES starting price must be between 0.01 and 0.99.'});
  }
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    const matchQ=await client.query(`INSERT INTO matches (event_name,event_day,format,side_a_name,side_b_name,scheduled_at,status) VALUES ($1,$2,$3,$4,$5,$6,'DRAFT') RETURNING *`,[event,day,fmt,isMulti?names[0]:a,isMulti?names[1]:b,scheduledAt||null]);
    const match=matchQ.rows[0];
    const question=isMulti?'Who will win?':`Will ${a} beat ${b}?`;
    const description=isMulti?`${event} · ${day} · Pick a winner`:`${event} · ${day} ${fmt}`;
    const marketQ=await client.query(`INSERT INTO markets (match_id,question,description,yes_price,opening_yes_price,liquidity,status,close_at,market_type) VALUES ($1,$2,$3,$4,$4,$5,'DRAFT',$6,$7) RETURNING *`,[match.id,question,description,isMulti?1/names.length:price,depth,closeAt||null,isMulti?'MULTI':'BINARY']);
    if(isMulti){
      const opening=1/names.length;
      for(let i=0;i<names.length;i++) await client.query(`INSERT INTO market_outcomes (market_id,outcome_key,label,price,opening_price,sort_order) VALUES ($1,$2,$3,$4,$4,$5)`,[marketQ.rows[0].id,normalizeOutcomeKey(names[i],i),names[i],opening,i]);
    }
    await client.query(`INSERT INTO audit_logs (actor,action,market_id,details) VALUES ('admin','CREATE_MATCH_MARKET',$1,$2)`,[marketQ.rows[0].id,JSON.stringify({matchId:match.id,event,day,format:fmt,sideA:a,sideB:b,scheduledAt,closeAt,yesPrice:price,liquidity:depth,marketType:isMulti?'MULTI':'BINARY',outcomes:names})]);
    await client.query('COMMIT'); res.json({match,market:marketQ.rows[0]});
  }catch(e){await client.query('ROLLBACK');res.status(400).json({error:e.message});}finally{client.release();}
});

app.post("/api/admin/matches/:id/publish", adminOnly, async (req, res) => {
  try { await assertSystemActive(); } catch (e) { return res.status(423).json({ error: e.message }); }
  const id = Number(req.params.id);
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const q = await client.query(`
      SELECT mt.id AS match_id, mt.status AS match_status, m.id AS market_id, m.status AS market_status
      FROM matches mt JOIN markets m ON m.match_id=mt.id
      WHERE mt.id=$1 FOR UPDATE OF mt, m
    `, [id]);
    if (!q.rows.length) throw new Error("Match not found.");
    const row = q.rows[0];
    if (row.match_status === "CANCELLED") throw new Error("Cancelled matches cannot be published.");
    await client.query("UPDATE matches SET status='SCHEDULED', updated_at=NOW() WHERE id=$1", [id]);
    await client.query("UPDATE markets SET status='TRADING', updated_at=NOW() WHERE match_id=$1", [id]);
    await client.query(`INSERT INTO audit_logs (actor, action, market_id, details) VALUES ('admin','PUBLISH_MATCH',$1,$2)`, [row.market_id, JSON.stringify({ matchId: id })]);
    await client.query("COMMIT");
    res.json({ ok: true, matchId: id, marketId: row.market_id, status: "TRADING" });
  } catch (e) {
    await client.query("ROLLBACK");
    res.status(400).json({ error: e.message });
  } finally {
    client.release();
  }
});

app.post("/api/admin/matches/:id/cancel", adminOnly, async (req, res) => {
  try { await assertSystemActive(); } catch (e) { return res.status(423).json({ error: e.message }); }
  const id = Number(req.params.id);
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const q = await client.query("SELECT mt.id, mt.status AS match_status, m.id AS market_id, m.status AS market_status FROM matches mt LEFT JOIN markets m ON m.match_id=mt.id WHERE mt.id=$1 FOR UPDATE", [id]);
    if (!q.rows.length) throw new Error("Match not found.");
    if (q.rows[0].match_status !== "DRAFT" || (q.rows[0].market_status && q.rows[0].market_status !== "DRAFT")) {
      throw new Error("Only unpublished draft matches can be cancelled here.");
    }
    await client.query("UPDATE matches SET status='CANCELLED', updated_at=NOW() WHERE id=$1", [id]);
    if (q.rows[0].market_id) await client.query("UPDATE markets SET status='VOID', updated_at=NOW(), result='VOID' WHERE id=$1", [q.rows[0].market_id]);
    await client.query(`INSERT INTO audit_logs (actor, action, market_id, details) VALUES ('admin','CANCEL_MATCH',$1,$2)`, [q.rows[0].market_id, JSON.stringify({ matchId: id })]);
    await client.query("COMMIT");
    res.json({ ok: true });
  } catch (e) {
    await client.query("ROLLBACK");
    res.status(400).json({ error: e.message });
  } finally {
    client.release();
  }
});

app.post("/api/admin/markets", adminOnly, async (req, res) => {
  try { await assertSystemActive(); } catch (e) { return res.status(423).json({ error: e.message }); }
  const { question, description = "", yesPrice = 0.50, closeAt = null, liquidity = 100 } = req.body || {};
  if (!question || String(question).trim().length < 5) return res.status(400).json({ error: "Question is required." });
  const price = Number(yesPrice);
  if (!Number.isFinite(price) || price < 0.01 || price > 0.99) return res.status(400).json({ error: "YES price must be between 0.01 and 0.99." });
  const depth = Number(liquidity);
  if (!Number.isFinite(depth) || depth < 10 || depth > 1000000) return res.status(400).json({ error: "Liquidity must be between $10 and $1,000,000." });

  const q = await pool.query(`
    INSERT INTO markets (question, description, yes_price, opening_yes_price, liquidity, status, close_at)
    VALUES ($1,$2,$3,$3,$4,'DRAFT',$5) RETURNING *
  `, [String(question).trim(), String(description), price, depth, closeAt || null]);

  await pool.query(`
    INSERT INTO audit_logs (actor, action, market_id, details)
    VALUES ('admin','CREATE_MARKET',$1,$2)
  `, [q.rows[0].id, JSON.stringify({ question })]);

  res.json(q.rows[0]);
});

app.post("/api/admin/markets/:id/status", adminOnly, async (req, res) => {
  try { await assertSystemActive(); } catch (e) { return res.status(423).json({ error: e.message }); }
  const allowed = ["DRAFT","OPEN","TRADING","CLOSED","AWAITING_RESULT","RESOLVED","SETTLED","VOID"];
  const status = String(req.body?.status || "").toUpperCase();
  if (!allowed.includes(status)) return res.status(400).json({ error: "Invalid status." });

  const id = Number(req.params.id);
  const q = await pool.query("UPDATE markets SET status=$1, updated_at=NOW() WHERE id=$2 RETURNING *", [status, id]);
  if (!q.rows.length) return res.status(404).json({ error: "Market not found." });
  if (["CLOSED","AWAITING_RESULT"].includes(status)) {
    const title = status === 'CLOSED' ? 'Trading closed' : 'Market awaiting result';
    const message = status === 'CLOSED' ? 'Trading has closed. Your open position remains active until the market is resolved and settled.' : 'The market is waiting for an official result. Your position is still open until settlement.';
    const client = await pool.connect();
    try { await client.query('BEGIN'); await notifyPositionHolders(client,id,'MARKET_STATUS',title,message); await client.query('COMMIT'); } catch(e){ await client.query('ROLLBACK'); } finally { client.release(); }
  }
  if (q.rows[0].match_id) {
    const matchStatus = status === "SETTLED" ? "COMPLETE" : status === "VOID" ? "CANCELLED" : status === "TRADING" || status === "OPEN" ? "SCHEDULED" : status === "CLOSED" || status === "AWAITING_RESULT" || status === "RESOLVED" ? "LIVE" : "DRAFT";
    await pool.query("UPDATE matches SET status=$1, updated_at=NOW() WHERE id=$2", [matchStatus, q.rows[0].match_id]);
  }

  await pool.query(`
    INSERT INTO audit_logs (actor, action, market_id, details)
    VALUES ('admin','STATUS_CHANGE',$1,$2)
  `, [id, JSON.stringify({ status })]);

  res.json(q.rows[0]);
});

app.post("/api/admin/markets/:id/result", adminOnly, async (req, res) => {
  try { await assertSystemActive(); } catch (e) { return res.status(423).json({ error: e.message }); }
  const result = String(req.body?.result || "").trim();
  if (!result) return res.status(400).json({ error: "A result is required." });

  const id = Number(req.params.id);
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const m = await client.query("SELECT * FROM markets WHERE id=$1 FOR UPDATE", [id]);
    if (!m.rows.length) throw new Error("Market not found.");
    if (!["CLOSED","AWAITING_RESULT","RESOLVED"].includes(m.rows[0].status)) throw new Error("Close the market before entering a result.");
    const market=m.rows[0];
    let resultLabel=result;
    if (market.market_type === 'MULTI') {
      const oq=await client.query("SELECT outcome_key,label FROM market_outcomes WHERE market_id=$1 ORDER BY sort_order,id",[id]);
      const chosen=oq.rows.find(o=>o.outcome_key===result);
      if(!chosen) throw new Error('Choose one of the listed outcomes.');
      resultLabel=chosen.label;
    } else if(!['YES','NO','VOID'].includes(result)) throw new Error('Result must be YES, NO, or VOID.');

    await client.query("UPDATE markets SET result=$1, status='RESOLVED', updated_at=NOW() WHERE id=$2", [result, id]);

    // Settlement is idempotent: only positions with quantity > 0 are paid.
    const positions = await client.query(
      "SELECT * FROM positions WHERE market_id=$1 AND quantity > 0 FOR UPDATE",
      [id]
    );

    for (const p of positions.rows) {
      let payout = 0;
      if (result !== "VOID") payout = p.side === result ? Number(p.quantity) : 0;
      else payout = Number(p.quantity) * Number(p.avg_cost);

      if (payout > 0) {
        const acctQ = await client.query("SELECT balance FROM accounts WHERE id=$1 FOR UPDATE", [p.account_id]);
        const balanceBefore = Number(acctQ.rows[0].balance);
        const balanceAfter = Number((balanceBefore + payout).toFixed(4));
        await client.query("UPDATE accounts SET balance=$1 WHERE id=$2", [balanceAfter, p.account_id]);
        await addLedgerEntry(client, {
          accountId: p.account_id, entryType: result === 'VOID' ? 'VOID_RETURN' : 'SETTLEMENT',
          amount: Number(payout.toFixed(4)), balanceBefore, balanceAfter, marketId: id,
          reference: `SETTLE_${result}`, details: { side: p.side, quantity: Number(p.quantity), result }
        });
      } else {
        const acctQ = await client.query("SELECT balance FROM accounts WHERE id=$1", [p.account_id]);
        const balance = Number(acctQ.rows[0]?.balance || 0);
        await addLedgerEntry(client, {
          accountId: p.account_id, entryType: 'SETTLEMENT_LOSS', amount: 0, balanceBefore: balance, balanceAfter: balance, marketId: id,
          reference: `SETTLE_${result}`, details: { side: p.side, quantity: Number(p.quantity), result }
        });
      }
      await addNotification(client, {
        accountId: p.account_id,
        type: 'SETTLEMENT',
        title: result === 'VOID' ? 'Market voided' : 'Market settled',
        message: result === 'VOID' ? 'Your position was returned at its cost basis because the market was voided.' : (p.side === result ? `Your position won and settled for ${Number(payout).toFixed(2)} virtual dollars.` : `Your position settled as a loss. Result: ${resultLabel}.`),
        marketId: id
      });
      await client.query("UPDATE positions SET quantity=0, avg_cost=0 WHERE account_id=$1 AND market_id=$2 AND side=$3", [p.account_id, id, p.side]);
    }

    await client.query("UPDATE markets SET status='SETTLED', updated_at=NOW() WHERE id=$1", [id]);
    const matchQ = await client.query("SELECT match_id FROM markets WHERE id=$1", [id]);
    if (matchQ.rows[0]?.match_id) await client.query("UPDATE matches SET status='COMPLETE', updated_at=NOW() WHERE id=$1", [matchQ.rows[0].match_id]);
    await client.query(`
      INSERT INTO audit_logs (actor, action, market_id, details)
      VALUES ('admin','SETTLE_MARKET',$1,$2)
    `, [id, JSON.stringify({ result, resultLabel, positionRows: positions.rowCount })]);

    await client.query("COMMIT");
    res.json({ ok: true, result, settled: positions.rowCount });
  } catch (e) {
    await client.query("ROLLBACK");
    res.status(400).json({ error: e.message });
  } finally {
    client.release();
  }
});

app.get("/api/admin/matches", adminOnly, async (_req, res) => {
  const q = await pool.query(`
    SELECT mt.*, m.id AS market_id, m.status AS market_status, m.yes_price, m.close_at, m.result,
      COALESCE((SELECT SUM(gross) FROM trades t WHERE t.market_id=m.id),0) AS volume,
      COALESCE((SELECT COUNT(*) FROM trades t WHERE t.market_id=m.id),0) AS trade_count,
      COALESCE((SELECT json_agg(json_build_object('outcome_key',mo.outcome_key,'label',mo.label,'price',mo.price,'opening_price',mo.opening_price,'sort_order',mo.sort_order) ORDER BY mo.sort_order,mo.id) FROM market_outcomes mo WHERE mo.market_id=m.id),'[]'::json) AS outcomes
    FROM matches mt
    LEFT JOIN markets m ON m.match_id=mt.id
    ORDER BY mt.id DESC
  `);
  res.json(q.rows);
});

app.get("/api/admin/audit", adminOnly, async (req, res) => {
  const page=Math.max(1,Number(req.query.page)||1);
  const pageSize=Math.min(100,Math.max(10,Number(req.query.pageSize)||40));
  const action=String(req.query.action||'').trim();
  const actor=String(req.query.actor||'').trim();
  const marketId=Number(req.query.marketId)||0;
  const where=[],params=[];
  if(action){if(action==='BUY'||action==='SELL'){params.push(action+'_%');where.push(`action LIKE $${params.length}`);}else if(action==='FREEZE'){params.push('GLOBAL_FREEZE_%');where.push(`action LIKE $${params.length}`);}else if(action==='STATUS'){params.push('STATUS_CHANGE');where.push(`action=$${params.length}`);}else if(action==='SETTLEMENT'){params.push('SETTLE_MARKET');where.push(`action=$${params.length}`);}else if(action==='ADMIN'){where.push(`(action NOT LIKE 'BUY_%' AND action NOT LIKE 'SELL_%' AND action NOT LIKE 'GLOBAL_FREEZE_%' AND action <> 'STATUS_CHANGE' AND action <> 'SETTLE_MARKET')`);}else{params.push(action);where.push(`action=$${params.length}`);}}
  if(actor){params.push(`%${actor}%`);where.push(`actor ILIKE $${params.length}`);}
  if(marketId){params.push(marketId);where.push(`market_id=$${params.length}`);}
  const clause=where.length?`WHERE ${where.join(' AND ')}`:'';
  const countQ=await pool.query(`SELECT COUNT(*)::int AS count FROM audit_logs ${clause}`,params);
  params.push(pageSize,pageSize*(page-1));
  const q=await pool.query(`SELECT * FROM audit_logs ${clause} ORDER BY id DESC LIMIT $${params.length-1} OFFSET $${params.length}`,params);
  res.json({rows:q.rows,total:countQ.rows[0].count,page,pageSize,pages:Math.max(1,Math.ceil(countQ.rows[0].count/pageSize))});
});

app.get("/admin", (_req, res) => res.sendFile(path.join(publicDir, "admin.html")));
app.use((_req, res) => res.sendFile(path.join(publicDir, "index.html")));

initDb()
  .then(() => {
    app.listen(PORT, () => console.log(`Ossper Markets listening on ${PORT}`));
  })
  .catch(err => {
    console.error("Database initialization failed:", err);
    process.exit(1);
  });
