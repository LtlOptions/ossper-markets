require("dotenv").config();

const crypto = require("crypto");
const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const session = require("express-session");
const path = require("path");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;

if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL is required.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

app.disable("x-powered-by");
app.use(helmet());
app.use(express.json({ limit: "50kb" }));
app.use(rateLimit({
  windowMs: 60 * 1000,
  max: 180,
  standardHeaders: true,
  legacyHeaders: false
}));

const sessionSecret = process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");
app.use(session({
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 1000 * 60 * 60 * 24 * 30
  }
}));

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  discord_id TEXT UNIQUE,
  role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user','admin')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS accounts (
  user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  balance_cents BIGINT NOT NULL DEFAULT 50000 CHECK (balance_cents >= 0),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ledger_entries (
  id BIGSERIAL PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  entry_type TEXT NOT NULL,
  amount_cents BIGINT NOT NULL,
  balance_after_cents BIGINT NOT NULL,
  reference_type TEXT,
  reference_id TEXT,
  description TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS markets (
  id UUID PRIMARY KEY,
  title TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'OPEN'
    CHECK (status IN ('DRAFT','OPEN','TRADING','CLOSED','AWAITING_RESULT','RESOLVED','SETTLED','VOID')),
  yes_price_cents INTEGER NOT NULL DEFAULT 50 CHECK (yes_price_cents BETWEEN 1 AND 99),
  q_yes DOUBLE PRECISION,
  q_no DOUBLE PRECISION,
  liquidity_b DOUBLE PRECISION NOT NULL DEFAULT 100,
  volume_cents BIGINT NOT NULL DEFAULT 0 CHECK (volume_cents >= 0),
  closes_at TIMESTAMPTZ,
  outcome TEXT CHECK (outcome IN ('YES','NO') OR outcome IS NULL),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS positions (
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  market_id UUID NOT NULL REFERENCES markets(id) ON DELETE CASCADE,
  yes_contracts INTEGER NOT NULL DEFAULT 0 CHECK (yes_contracts >= 0),
  no_contracts INTEGER NOT NULL DEFAULT 0 CHECK (no_contracts >= 0),
  yes_cost_cents BIGINT NOT NULL DEFAULT 0 CHECK (yes_cost_cents >= 0),
  no_cost_cents BIGINT NOT NULL DEFAULT 0 CHECK (no_cost_cents >= 0),
  realized_pnl_cents BIGINT NOT NULL DEFAULT 0,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (user_id, market_id)
);

CREATE TABLE IF NOT EXISTS trades (
  id BIGSERIAL PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  market_id UUID NOT NULL REFERENCES markets(id) ON DELETE CASCADE,
  side TEXT NOT NULL CHECK (side IN ('YES','NO')),
  action TEXT NOT NULL CHECK (action IN ('BUY','SELL')),
  contracts INTEGER NOT NULL CHECK (contracts > 0),
  price_cents INTEGER NOT NULL CHECK (price_cents BETWEEN 1 AND 99),
  total_cents BIGINT NOT NULL CHECK (total_cents >= 0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS market_events (
  id BIGSERIAL PRIMARY KEY,
  market_id UUID NOT NULL REFERENCES markets(id) ON DELETE CASCADE,
  event_type TEXT NOT NULL,
  actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ledger_user_created ON ledger_entries(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_trades_market_created ON trades(market_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_market_created ON market_events(market_id, created_at DESC);
`;

function dollars(cents) {
  return Number(cents) / 100;
}

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

/*
  Ossper automated liquidity model: LMSR (logarithmic market scoring rule).
  This gives us real price impact instead of the old linear price-jump demo.
  YES + NO always equals $1.00.

  Important anti-scalping properties:
  - Buying moves the marginal price against the buyer.
  - Selling moves it back against the seller.
  - A buy-then-immediate-sell round trip cannot create money from price movement.
  - A small trading fee and short market cooldown add friction to rapid churn.
*/
const TRADING_FEE_BPS = 100; // 1.00% per executed trade
const TRADE_COOLDOWN_SECONDS = 10;
const MAX_POSITION_CONTRACTS = 500;
const LIQUIDITY_B_DEFAULT = 100;

function lmsrCost(qYes, qNo, b) {
  const a = qYes / b;
  const c = qNo / b;
  const max = Math.max(a, c);
  return b * (max + Math.log(Math.exp(a - max) + Math.exp(c - max)));
}

function lmsrPrice(qYes, qNo, b, side) {
  const a = qYes / b;
  const c = qNo / b;
  const max = Math.max(a, c);
  const ea = Math.exp(a - max);
  const ec = Math.exp(c - max);
  const yes = ea / (ea + ec);
  return side === 'YES' ? yes : 1 - yes;
}

function lmsrTrade(qYes, qNo, b, side, action, contracts) {
  const before = lmsrCost(qYes, qNo, b);
  const sign = action === 'BUY' ? 1 : -1;
  const nextYes = qYes + (side === 'YES' ? sign * contracts : 0);
  const nextNo = qNo + (side === 'NO' ? sign * contracts : 0);
  const after = lmsrCost(nextYes, nextNo, b);
  const delta = after - before;
  const grossCents = Math.max(1, Math.round(Math.abs(delta) * 100));
  return { nextYes, nextNo, grossCents, averagePrice: grossCents / contracts / 100 };
}

function feeFor(grossCents) {
  return Math.max(1, Math.ceil(grossCents * TRADING_FEE_BPS / 10000));
}

async function ensureSchemaAndSeed() {
  await pool.query(SCHEMA_SQL);
  // Safe migrations for databases created by earlier Ossper versions.
  await pool.query(`ALTER TABLE positions ADD COLUMN IF NOT EXISTS realized_pnl_cents BIGINT NOT NULL DEFAULT 0`);
  await pool.query(`ALTER TABLE markets ADD COLUMN IF NOT EXISTS q_yes DOUBLE PRECISION`);
  await pool.query(`ALTER TABLE markets ADD COLUMN IF NOT EXISTS q_no DOUBLE PRECISION`);
  await pool.query(`ALTER TABLE markets ADD COLUMN IF NOT EXISTS liquidity_b DOUBLE PRECISION NOT NULL DEFAULT 100`);
  await pool.query(`ALTER TABLE trades ADD COLUMN IF NOT EXISTS fee_cents BIGINT NOT NULL DEFAULT 0`);
  await pool.query(`UPDATE markets SET q_yes = liquidity_b * LN(yes_price_cents::double precision / (100 - yes_price_cents)::double precision), q_no = 0 WHERE q_yes IS NULL OR q_no IS NULL`);

  const demoId = "00000000-0000-4000-8000-000000000001";
  const marketId = "00000000-0000-4000-8000-000000000101";

  await pool.query(
    `INSERT INTO users (id, username, role)
     VALUES ($1, 'Ossper Demo', 'user')
     ON CONFLICT (id) DO NOTHING`,
    [demoId]
  );

  const accountResult = await pool.query(
    `SELECT user_id FROM accounts WHERE user_id = $1`,
    [demoId]
  );

  if (accountResult.rowCount === 0) {
    await pool.query(
      `INSERT INTO accounts (user_id, balance_cents) VALUES ($1, 50000)`,
      [demoId]
    );
    await pool.query(
      `INSERT INTO ledger_entries
       (user_id, entry_type, amount_cents, balance_after_cents, reference_type, reference_id, description)
       VALUES ($1, 'INITIAL_BALANCE', 50000, 50000, 'ACCOUNT', $1, 'Ossper virtual starting balance')`,
      [demoId]
    );
  }

  await pool.query(
    `INSERT INTO markets
      (id, title, description, status, yes_price_cents, closes_at)
     VALUES
      ($1, 'Will Player A win Friday 1v1?', 'Demo market — virtual money only. This is a test market for the Ossper engine.', 'TRADING', 64, NOW() + INTERVAL '7 days')
     ON CONFLICT (id) DO NOTHING`,
    [marketId]
  );
}

async function getDemoUser(req) {
  const id = "00000000-0000-4000-8000-000000000001";
  req.session.userId = id;
  return id;
}

app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ status: "ok", database: "connected", virtualMoneyOnly: true });
  } catch (error) {
    console.error(error);
    res.status(503).json({ status: "error", database: "unavailable" });
  }
});

app.get("/api/me", async (req, res) => {
  try {
    const userId = await getDemoUser(req);
    const result = await pool.query(
      `SELECT u.id, u.username, u.role, a.balance_cents
       FROM users u JOIN accounts a ON a.user_id = u.id
       WHERE u.id = $1`,
      [userId]
    );
    res.json({
      user: {
        id: result.rows[0].id,
        username: result.rows[0].username,
        role: result.rows[0].role
      },
      balance: dollars(result.rows[0].balance_cents)
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Unable to load account" });
  }
});

app.get("/api/markets", async (req, res) => {
  try {
    const userId = await getDemoUser(req);
    const markets = await pool.query(
      `SELECT m.*,
              COALESCE(p.yes_contracts, 0) AS yes_contracts,
              COALESCE(p.no_contracts, 0) AS no_contracts,
              COALESCE(p.yes_cost_cents, 0) AS yes_cost_cents,
              COALESCE(p.no_cost_cents, 0) AS no_cost_cents,
              COALESCE(p.realized_pnl_cents, 0) AS realized_pnl_cents
       FROM markets m
       LEFT JOIN positions p
         ON p.market_id = m.id AND p.user_id = $1
       WHERE m.status IN ('OPEN','TRADING','CLOSED')
       ORDER BY m.created_at DESC`,
      [userId]
    );

    res.json({
      markets: markets.rows.map(m => ({
        id: m.id,
        title: m.title,
        description: m.description,
        status: m.status,
        yesPrice: m.yes_price_cents / 100,
        noPrice: (100 - m.yes_price_cents) / 100,
        volume: dollars(m.volume_cents),
        closesAt: m.closes_at,
        position: {
          yesContracts: Number(m.yes_contracts),
          noContracts: Number(m.no_contracts),
          yesCost: dollars(m.yes_cost_cents),
          noCost: dollars(m.no_cost_cents),
          yesAvgPrice: Number(m.yes_contracts) ? dollars(Math.round(Number(m.yes_cost_cents) / Number(m.yes_contracts))) : 0,
          noAvgPrice: Number(m.no_contracts) ? dollars(Math.round(Number(m.no_cost_cents) / Number(m.no_contracts))) : 0,
          yesValue: dollars(Number(m.yes_contracts) * Number(m.yes_price_cents)),
          noValue: dollars(Number(m.no_contracts) * (100 - Number(m.yes_price_cents))),
          yesUnrealizedPnl: dollars(Number(m.yes_contracts) * Number(m.yes_price_cents) - Number(m.yes_cost_cents)),
          noUnrealizedPnl: dollars(Number(m.no_contracts) * (100 - Number(m.yes_price_cents)) - Number(m.no_cost_cents)),
          realizedPnl: dollars(Number(m.realized_pnl_cents))
        }
      }))
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Unable to load markets" });
  }
});

app.post("/api/trades", async (req, res) => {
  const client = await pool.connect();
  try {
    const userId = await getDemoUser(req);
    const { marketId, side, action, contracts } = req.body;
    const qty = Number(contracts);

    if (!marketId || !["YES", "NO"].includes(side) || !["BUY", "SELL"].includes(action)) {
      return res.status(400).json({ error: "Invalid trade request" });
    }
    if (!Number.isInteger(qty) || qty < 1 || qty > 100) {
      return res.status(400).json({ error: "Contracts must be a whole number from 1 to 100" });
    }

    await client.query("BEGIN");

    const marketResult = await client.query(
      `SELECT * FROM markets WHERE id = $1 FOR UPDATE`,
      [marketId]
    );
    if (!marketResult.rowCount) throw new Error("Market not found");

    const market = marketResult.rows[0];
    if (market.status !== "TRADING") throw new Error("Market is not currently trading");

    const b = Number(market.liquidity_b || LIQUIDITY_B_DEFAULT);
    const qYes = Number(market.q_yes);
    const qNo = Number(market.q_no);
    if (!Number.isFinite(qYes) || !Number.isFinite(qNo) || b <= 0) {
      throw new Error("Market liquidity state is invalid");
    }

    const currentPriceFloat = lmsrPrice(qYes, qNo, b, side);
    const currentPriceCents = Math.max(1, Math.min(99, Math.round(currentPriceFloat * 100)));

    const accountResult = await client.query(
      `SELECT * FROM accounts WHERE user_id = $1 FOR UPDATE`,
      [userId]
    );
    const account = accountResult.rows[0];

    const positionResult = await client.query(
      `SELECT * FROM positions WHERE user_id = $1 AND market_id = $2 FOR UPDATE`,
      [userId, marketId]
    );

    let position = positionResult.rows[0];
    if (!position) {
      const inserted = await client.query(
        `INSERT INTO positions (user_id, market_id) VALUES ($1, $2) RETURNING *`,
        [userId, marketId]
      );
      position = inserted.rows[0];
    }

    const recentTrade = await client.query(
      `SELECT created_at FROM trades WHERE user_id=$1 AND market_id=$2 ORDER BY created_at DESC LIMIT 1`,
      [userId, marketId]
    );
    if (recentTrade.rowCount) {
      const elapsedSeconds = (Date.now() - new Date(recentTrade.rows[0].created_at).getTime()) / 1000;
      if (elapsedSeconds < TRADE_COOLDOWN_SECONDS) {
        const wait = Math.ceil(TRADE_COOLDOWN_SECONDS - elapsedSeconds);
        throw new Error(`Slow down — wait ${wait}s before trading this market again.`);
      }
    }

    const ownedBefore = side === 'YES' ? Number(position.yes_contracts) : Number(position.no_contracts);
    if (action === 'BUY' && ownedBefore + qty > MAX_POSITION_CONTRACTS) {
      throw new Error(`Maximum position is ${MAX_POSITION_CONTRACTS} ${side} contracts.`);
    }

    const quote = lmsrTrade(qYes, qNo, b, side, action, qty);
    const feeCents = feeFor(quote.grossCents);
    const cashDelta = action === 'BUY' ? -(quote.grossCents + feeCents) : (quote.grossCents - feeCents);

    if (action === "BUY") {
      if (Number(account.balance_cents) < quote.grossCents + feeCents) {
        throw new Error("Insufficient virtual balance");
      }

      const newBalance = Number(account.balance_cents) - quote.grossCents - feeCents;
      await client.query(
        `UPDATE accounts SET balance_cents = $1, updated_at = NOW() WHERE user_id = $2`,
        [newBalance, userId]
      );

      const yesContracts = Number(position.yes_contracts) + (side === "YES" ? qty : 0);
      const noContracts = Number(position.no_contracts) + (side === "NO" ? qty : 0);
      const yesCost = Number(position.yes_cost_cents) + (side === "YES" ? quote.grossCents + feeCents : 0);
      const noCost = Number(position.no_cost_cents) + (side === "NO" ? quote.grossCents + feeCents : 0);

      await client.query(
        `UPDATE positions
         SET yes_contracts=$1, no_contracts=$2, yes_cost_cents=$3, no_cost_cents=$4, updated_at=NOW()
         WHERE user_id=$5 AND market_id=$6`,
        [yesContracts, noContracts, yesCost, noCost, userId, marketId]
      );

      await client.query(
        `INSERT INTO ledger_entries
         (user_id, entry_type, amount_cents, balance_after_cents, reference_type, reference_id, description)
         VALUES ($1, 'TRADE_BUY', $2, $3, 'TRADE', 'pending', $4)`,
        [userId, -(quote.grossCents + feeCents), newBalance, `Bought ${qty} ${side} contract(s) + 1.00% fee`]
      );
    } else {
      const owned = side === "YES" ? Number(position.yes_contracts) : Number(position.no_contracts);
      if (owned < qty) throw new Error(`You only own ${owned} ${side} contract(s)`);

      const newBalance = Number(account.balance_cents) + quote.grossCents - feeCents;
      await client.query(
        `UPDATE accounts SET balance_cents = $1, updated_at = NOW() WHERE user_id = $2`,
        [newBalance, userId]
      );

      const costBasisPool = side === "YES" ? Number(position.yes_cost_cents) : Number(position.no_cost_cents);
      // Realized P/L is based on the contracts' average entry cost, not the sale proceeds.
      const costBasisSold = Math.round(costBasisPool * qty / owned);
      const realizedPnl = (quote.grossCents - feeCents) - costBasisSold;

      const yesContracts = Number(position.yes_contracts) - (side === "YES" ? qty : 0);
      const noContracts = Number(position.no_contracts) - (side === "NO" ? qty : 0);
      const yesCost = Math.max(0, Number(position.yes_cost_cents) - (side === "YES" ? costBasisSold : 0));
      const noCost = Math.max(0, Number(position.no_cost_cents) - (side === "NO" ? costBasisSold : 0));
      const realizedTotal = Number(position.realized_pnl_cents) + realizedPnl;

      await client.query(
        `UPDATE positions
         SET yes_contracts=$1, no_contracts=$2, yes_cost_cents=$3, no_cost_cents=$4, realized_pnl_cents=$5, updated_at=NOW()
         WHERE user_id=$6 AND market_id=$7`,
        [yesContracts, noContracts, yesCost, noCost, realizedTotal, userId, marketId]
      );

      await client.query(
        `INSERT INTO ledger_entries
         (user_id, entry_type, amount_cents, balance_after_cents, reference_type, reference_id, description)
         VALUES ($1, 'TRADE_SELL', $2, $3, 'TRADE', 'pending', $4)`,
        [userId, quote.grossCents - feeCents, newBalance, `Sold ${qty} ${side} contract(s) - 1.00% fee`]
      );
    }

    const tradeResult = await client.query(
      `INSERT INTO trades (user_id, market_id, side, action, contracts, price_cents, total_cents, fee_cents)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
       RETURNING id`,
      [userId, marketId, side, action, qty, Math.max(1, Math.min(99, Math.round(quote.averagePrice * 100))), quote.grossCents, feeCents]
    );
    const tradeId = tradeResult.rows[0].id;

    await client.query(
      `UPDATE ledger_entries
       SET reference_id = $1
       WHERE user_id=$2 AND reference_type='TRADE' AND reference_id='pending'
       AND created_at = (SELECT MAX(created_at) FROM ledger_entries WHERE user_id=$2 AND reference_type='TRADE' AND reference_id='pending')`,
      [String(tradeId), userId]
    );

    const newYesFloat = lmsrPrice(quote.nextYes, quote.nextNo, b, 'YES');
    const newYesCents = Math.max(1, Math.min(99, Math.round(newYesFloat * 100)));
    await client.query(
      `UPDATE markets
       SET q_yes=$1, q_no=$2, yes_price_cents=$3, volume_cents=volume_cents+$4, updated_at=NOW()
       WHERE id=$5`,
      [quote.nextYes, quote.nextNo, newYesCents, quote.grossCents, marketId]
    );

    await client.query("COMMIT");

    res.json({
      success: true,
      trade: {
        id: tradeId,
        side,
        action,
        contracts: qty,
        price: quote.averagePrice,
        total: dollars(quote.grossCents),
        fee: dollars(feeCents),
        netCash: dollars(action === 'BUY' ? -(quote.grossCents + feeCents) : (quote.grossCents - feeCents))
      },
      newYesPrice: newYesCents / 100,
      newNoPrice: (100 - newYesCents) / 100,
      fee: dollars(feeCents),
      cooldownSeconds: TRADE_COOLDOWN_SECONDS
    });
  } catch (error) {
    await client.query("ROLLBACK");
    console.error(error);
    res.status(400).json({ error: error.message || "Trade failed" });
  } finally {
    client.release();
  }
});

app.get("/api/history", async (req, res) => {
  try {
    const userId = await getDemoUser(req);
    const result = await pool.query(
      `SELECT t.id, t.side, t.action, t.contracts, t.price_cents, t.total_cents, t.fee_cents, t.created_at, m.title
       FROM trades t JOIN markets m ON m.id=t.market_id
       WHERE t.user_id=$1
       ORDER BY t.created_at DESC
       LIMIT 25`,
      [userId]
    );
    res.json({
      trades: result.rows.map(t => ({
        id: t.id,
        title: t.title,
        side: t.side,
        action: t.action,
        contracts: Number(t.contracts),
        price: Number(t.price_cents) / 100,
        total: dollars(t.total_cents),
        fee: dollars(t.fee_cents || 0),
        createdAt: t.created_at
      }))
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Unable to load history" });
  }
});

app.use(express.static(path.join(__dirname)));

ensureSchemaAndSeed()
  .then(() => {
    app.listen(PORT, "0.0.0.0", () => {
      console.log(`Ossper Markets listening on port ${PORT}`);
    });
  })
  .catch(error => {
    console.error("Database initialization failed:", error);
    process.exit(1);
  });
