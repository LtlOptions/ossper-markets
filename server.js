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

function adminOnly(req, res, next) {
  const token = req.headers.authorization?.replace(/^Bearer\s+/i, "") || adminCookie(req);
  const payload = readToken(token);
  if (!payload) return res.status(401).json({ error: "Admin authentication required." });
  req.admin = payload;
  next();
}

function setAdminCookie(res, token) {
  res.setHeader("Set-Cookie", `ossper_admin=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=28800`);
}

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS markets (
      id SERIAL PRIMARY KEY,
      question TEXT NOT NULL,
      description TEXT NOT NULL DEFAULT '',
      yes_price NUMERIC(10,4) NOT NULL DEFAULT 0.50,
      status TEXT NOT NULL DEFAULT 'DRAFT',
      close_at TIMESTAMPTZ,
      result TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CHECK (yes_price >= 0.01 AND yes_price <= 0.99),
      CHECK (status IN ('DRAFT','OPEN','TRADING','CLOSED','AWAITING_RESULT','RESOLVED','SETTLED','VOID')),
      CHECK (result IS NULL OR result IN ('YES','NO','VOID'))
    );

    CREATE TABLE IF NOT EXISTS accounts (
      id UUID PRIMARY KEY,
      balance NUMERIC(18,4) NOT NULL DEFAULT 500.00,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

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
  `);

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

async function marketSnapshot(marketId, accountId) {
  const marketQ = await pool.query("SELECT * FROM markets WHERE id=$1", [marketId]);
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

  const volumeQ = await pool.query(
    "SELECT COALESCE(SUM(gross),0) AS volume FROM trades WHERE market_id=$1",
    [marketId]
  );

  const account = await getAccount(accountId);
  const yes = Number(market.yes_price);
  return {
    market: {
      ...market,
      yes_price: yes,
      no_price: Number((1 - yes).toFixed(4)),
      volume: Number(volumeQ.rows[0].volume),
    },
    account: {
      balance: Number(account.balance),
      positions: positionsQ.rows.map(p => ({
        side: p.side,
        quantity: Number(p.quantity),
        avg_cost: Number(p.avg_cost),
        realized_pnl: Number(p.realized_pnl),
      })),
      trades: tradesQ.rows.map(t => ({
        ...t,
        quantity: Number(t.quantity),
        price: Number(t.price),
        gross: Number(t.gross),
        fee: Number(t.fee),
      })),
    }
  };
}

function clampPrice(p) {
  return Math.max(0.01, Math.min(0.99, Number(p.toFixed(4))));
}

async function executeTrade({ accountId, marketId, action, side, quantity }) {
  quantity = Math.floor(Number(quantity));
  if (!Number.isInteger(quantity) || quantity <= 0 || quantity > 10000) {
    throw new Error("Quantity must be a whole number from 1 to 10,000.");
  }
  side = String(side).toUpperCase();
  action = String(action).toUpperCase();
  if (!["YES","NO"].includes(side) || !["BUY","SELL"].includes(action)) throw new Error("Invalid trade.");

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const m = await client.query("SELECT * FROM markets WHERE id=$1 FOR UPDATE", [marketId]);
    if (!m.rows.length) throw new Error("Market not found.");
    const market = m.rows[0];
    if (!["OPEN","TRADING"].includes(market.status)) throw new Error("Trading is closed for this market.");

    const accountQ = await client.query("SELECT * FROM accounts WHERE id=$1 FOR UPDATE", [accountId]);
    if (!accountQ.rows.length) throw new Error("Account not found.");
    const account = accountQ.rows[0];

    const yes = Number(market.yes_price);
    const price = side === "YES" ? yes : 1 - yes;
    const gross = Number((price * quantity).toFixed(4));
    const fee = Number((gross * 0.01).toFixed(4));

    const posQ = await client.query(
      "SELECT * FROM positions WHERE account_id=$1 AND market_id=$2 AND side=$3 FOR UPDATE",
      [accountId, marketId, side]
    );
    const current = posQ.rows[0] || { quantity: 0, avg_cost: 0, realized_pnl: 0 };
    const currentQty = Number(current.quantity);
    const currentAvg = Number(current.avg_cost);

    if (action === "BUY") {
      const totalDebit = Number((gross + fee).toFixed(4));
      if (Number(account.balance) + 1e-9 < totalDebit) throw new Error("Insufficient balance.");
      if (quantity > 10000) throw new Error("Position limit exceeded.");

      const newQty = currentQty + quantity;
      const newAvg = ((currentQty * currentAvg) + gross) / newQty;
      await client.query("UPDATE accounts SET balance = balance - $1 WHERE id=$2", [totalDebit, accountId]);
      await client.query(`
        INSERT INTO positions (account_id, market_id, side, quantity, avg_cost)
        VALUES ($1,$2,$3,$4,$5)
        ON CONFLICT (account_id, market_id, side)
        DO UPDATE SET quantity=EXCLUDED.quantity, avg_cost=EXCLUDED.avg_cost
      `, [accountId, marketId, side, newQty, newAvg]);
    } else {
      if (currentQty < quantity) throw new Error(`You only own ${currentQty} ${side} contracts.`);
      const netCredit = Number((gross - fee).toFixed(4));
      const newQty = currentQty - quantity;
      const realized = Number((gross - (currentAvg * quantity) - fee).toFixed(4));
      await client.query("UPDATE accounts SET balance = balance + $1 WHERE id=$2", [netCredit, accountId]);
      await client.query(`
        INSERT INTO positions (account_id, market_id, side, quantity, avg_cost, realized_pnl)
        VALUES ($1,$2,$3,$4,$5,$6)
        ON CONFLICT (account_id, market_id, side)
        DO UPDATE SET quantity=EXCLUDED.quantity, avg_cost=EXCLUDED.avg_cost, realized_pnl=positions.realized_pnl + EXCLUDED.realized_pnl
      `, [accountId, marketId, side, newQty, newQty ? currentAvg : 0, realized]);
    }

    // Small deterministic price impact for the demo AMM.
    const direction = action === "BUY" ? 1 : -1;
    const sideDirection = side === "YES" ? 1 : -1;
    const impact = Math.min(0.03, quantity * 0.00015);
    const nextYes = clampPrice(yes + direction * sideDirection * impact);
    await client.query("UPDATE markets SET yes_price=$1, updated_at=NOW() WHERE id=$2", [nextYes, marketId]);

    await client.query(`
      INSERT INTO trades (account_id, market_id, side, action, quantity, price, gross, fee)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
    `, [accountId, marketId, side, action, quantity, price, gross, fee]);

    await client.query(`
      INSERT INTO audit_logs (actor, action, market_id, details)
      VALUES ($1,$2,$3,$4)
    `, [accountId, `${action}_${side}`, marketId, JSON.stringify({ quantity, price, gross, fee })]);

    await client.query("COMMIT");
    return await marketSnapshot(marketId, accountId);
  } catch (e) {
    await client.query("ROLLBACK");
    throw e;
  } finally {
    client.release();
  }
}

app.get("/api/health", async (_req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true, database: true, service: "ossper-markets" });
  } catch {
    res.status(503).json({ ok: false, database: false });
  }
});

app.post("/api/session", async (_req, res) => {
  const id = crypto.randomUUID();
  await ensureAccount(id);
  res.json({ accountId: id });
});

app.get("/api/markets", async (req, res) => {
  const accountId = req.header("x-account-id");
  if (!accountId) return res.status(400).json({ error: "Missing account." });
  await ensureAccount(accountId);
  const q = await pool.query("SELECT * FROM markets ORDER BY id DESC");
  const out = [];
  for (const m of q.rows) {
    const snap = await marketSnapshot(m.id, accountId);
    out.push(snap);
  }
  res.json(out);
});

app.get("/api/market/:id", async (req, res) => {
  const accountId = req.header("x-account-id");
  if (!accountId) return res.status(400).json({ error: "Missing account." });
  await ensureAccount(accountId);
  const snap = await marketSnapshot(Number(req.params.id), accountId);
  if (!snap) return res.status(404).json({ error: "Market not found." });
  res.json(snap);
});

app.post("/api/trade", async (req, res) => {
  try {
    const accountId = req.header("x-account-id");
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

app.get("/api/admin/me", adminOnly, (_req, res) => res.json({ ok: true, role: "admin" }));

app.get("/api/admin/markets", adminOnly, async (_req, res) => {
  const q = await pool.query(`
    SELECT m.*,
      COALESCE((SELECT SUM(gross) FROM trades t WHERE t.market_id=m.id),0) AS volume,
      COALESCE((SELECT COUNT(*) FROM trades t WHERE t.market_id=m.id),0) AS trade_count
    FROM markets m
    ORDER BY m.id DESC
  `);
  res.json(q.rows);
});

app.post("/api/admin/markets", adminOnly, async (req, res) => {
  const { question, description = "", yesPrice = 0.50, closeAt = null } = req.body || {};
  if (!question || String(question).trim().length < 5) return res.status(400).json({ error: "Question is required." });
  const price = Number(yesPrice);
  if (!Number.isFinite(price) || price < 0.01 || price > 0.99) return res.status(400).json({ error: "YES price must be between 0.01 and 0.99." });

  const q = await pool.query(`
    INSERT INTO markets (question, description, yes_price, status, close_at)
    VALUES ($1,$2,$3,'DRAFT',$4) RETURNING *
  `, [String(question).trim(), String(description), price, closeAt || null]);

  await pool.query(`
    INSERT INTO audit_logs (actor, action, market_id, details)
    VALUES ('admin','CREATE_MARKET',$1,$2)
  `, [q.rows[0].id, JSON.stringify({ question })]);

  res.json(q.rows[0]);
});

app.post("/api/admin/markets/:id/status", adminOnly, async (req, res) => {
  const allowed = ["DRAFT","OPEN","TRADING","CLOSED","AWAITING_RESULT","RESOLVED","SETTLED","VOID"];
  const status = String(req.body?.status || "").toUpperCase();
  if (!allowed.includes(status)) return res.status(400).json({ error: "Invalid status." });

  const id = Number(req.params.id);
  const q = await pool.query("UPDATE markets SET status=$1, updated_at=NOW() WHERE id=$2 RETURNING *", [status, id]);
  if (!q.rows.length) return res.status(404).json({ error: "Market not found." });

  await pool.query(`
    INSERT INTO audit_logs (actor, action, market_id, details)
    VALUES ('admin','STATUS_CHANGE',$1,$2)
  `, [id, JSON.stringify({ status })]);

  res.json(q.rows[0]);
});

app.post("/api/admin/markets/:id/result", adminOnly, async (req, res) => {
  const result = String(req.body?.result || "").toUpperCase();
  if (!["YES","NO","VOID"].includes(result)) return res.status(400).json({ error: "Result must be YES, NO, or VOID." });

  const id = Number(req.params.id);
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const m = await client.query("SELECT * FROM markets WHERE id=$1 FOR UPDATE", [id]);
    if (!m.rows.length) throw new Error("Market not found.");
    if (!["CLOSED","AWAITING_RESULT","RESOLVED"].includes(m.rows[0].status)) {
      throw new Error("Close the market before entering a result.");
    }

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
        await client.query("UPDATE accounts SET balance=balance+$1 WHERE id=$2", [payout, p.account_id]);
      }
      await client.query(
        "UPDATE positions SET quantity=0, avg_cost=0 WHERE account_id=$1 AND market_id=$2 AND side=$3",
        [p.account_id, id, p.side]
      );
    }

    await client.query("UPDATE markets SET status='SETTLED', updated_at=NOW() WHERE id=$1", [id]);
    await client.query(`
      INSERT INTO audit_logs (actor, action, market_id, details)
      VALUES ('admin','SETTLE_MARKET',$1,$2)
    `, [id, JSON.stringify({ result, positionRows: positions.rowCount })]);

    await client.query("COMMIT");
    res.json({ ok: true, result, settled: positions.rowCount });
  } catch (e) {
    await client.query("ROLLBACK");
    res.status(400).json({ error: e.message });
  } finally {
    client.release();
  }
});

app.get("/api/admin/audit", adminOnly, async (_req, res) => {
  const q = await pool.query("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 200");
  res.json(q.rows);
});

app.get("/admin", (_req, res) => res.sendFile(path.join(publicDir, "admin.html")));
app.get("*", (_req, res) => res.sendFile(path.join(publicDir, "index.html")));

initDb()
  .then(() => {
    app.listen(PORT, () => console.log(`Ossper Markets listening on ${PORT}`));
  })
  .catch(err => {
    console.error("Database initialization failed:", err);
    process.exit(1);
  });
