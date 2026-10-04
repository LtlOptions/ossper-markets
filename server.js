const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { Pool } = require("pg");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");

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

async function adminOrModerator(req, res, next) {
  return adminOnly(req, res, () => {
    if (req.admin?.source === "admin_key") return next();
    if (["owner","admin","moderator"].includes(req.admin?.role)) return next();
    return res.status(403).json({ error: "Admin or moderator access required." });
  });
}

async function adminOrOwner(req, res, next) {
  return adminOnly(req, res, () => {
    if (req.admin?.source === "admin_key") return next();
    if (["owner","admin"].includes(req.admin?.role)) return next();
    return res.status(403).json({ error: "Admin access required." });
  });
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
      CHECK (role IN ('owner','admin','moderator'))
    );
    CREATE INDEX IF NOT EXISTS admin_roles_discord_idx ON admin_roles(discord_id);
    CREATE UNIQUE INDEX IF NOT EXISTS admin_roles_active_discord_idx ON admin_roles(discord_id) WHERE revoked_at IS NULL;
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS seasons (
      id UUID PRIMARY KEY,
      season_number INTEGER NOT NULL UNIQUE,
      name TEXT NOT NULL,
      description TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL DEFAULT 'DRAFT',
      starting_balance NUMERIC(18,4) NOT NULL DEFAULT 10000.0000,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      registration_open_at TIMESTAMPTZ,
      started_at TIMESTAMPTZ,
      ended_at TIMESTAMPTZ,
      archived_at TIMESTAMPTZ,
      created_by TEXT NOT NULL DEFAULT 'admin',
      CHECK (status IN ('DRAFT','REGISTRATION','LIVE','PAUSED','COMPLETED','ARCHIVED')),
      CHECK (starting_balance >= 0)
    );
    CREATE INDEX IF NOT EXISTS seasons_status_idx ON seasons(status, created_at DESC);
    ALTER TABLE seasons ADD COLUMN IF NOT EXISTS tournament_run INTEGER NOT NULL DEFAULT 1;

    CREATE TABLE IF NOT EXISTS season_players (
      id UUID PRIMARY KEY,
      season_id UUID NOT NULL REFERENCES seasons(id) ON DELETE RESTRICT,
      account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
      starting_balance NUMERIC(18,4) NOT NULL,
      current_balance NUMERIC(18,4) NOT NULL,
      joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      status TEXT NOT NULL DEFAULT 'ACTIVE',
      final_rank INTEGER,
      final_points NUMERIC(18,4),
      UNIQUE (season_id, account_id),
      CHECK (status IN ('ACTIVE','SUSPENDED','REMOVED'))
    );
    CREATE INDEX IF NOT EXISTS season_players_season_idx ON season_players(season_id, status);
    CREATE INDEX IF NOT EXISTS season_players_account_idx ON season_players(account_id, joined_at DESC);
    ALTER TABLE season_players ADD COLUMN IF NOT EXISTS locked_balance NUMERIC(18,4) NOT NULL DEFAULT 0;
    ALTER TABLE season_players ADD COLUMN IF NOT EXISTS realized_pnl NUMERIC(18,4) NOT NULL DEFAULT 0;
    ALTER TABLE season_players ADD COLUMN IF NOT EXISTS total_wagered NUMERIC(18,4) NOT NULL DEFAULT 0;
    ALTER TABLE season_players ADD COLUMN IF NOT EXISTS total_winnings NUMERIC(18,4) NOT NULL DEFAULT 0;
    ALTER TABLE season_players ADD COLUMN IF NOT EXISTS total_losses NUMERIC(18,4) NOT NULL DEFAULT 0;
    CREATE INDEX IF NOT EXISTS season_players_status_idx ON season_players(season_id, status, joined_at DESC);

    CREATE TABLE IF NOT EXISTS season_wallet_entries (
      id BIGSERIAL PRIMARY KEY,
      season_id UUID NOT NULL REFERENCES seasons(id) ON DELETE RESTRICT,
      account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
      type TEXT NOT NULL,
      amount NUMERIC(18,4) NOT NULL,
      balance_after NUMERIC(18,4) NOT NULL,
      reference_type TEXT,
      reference_id TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS season_wallet_entries_season_idx ON season_wallet_entries(season_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS season_wallet_entries_account_idx ON season_wallet_entries(account_id, season_id, created_at DESC);

    CREATE TABLE IF NOT EXISTS season_matches (
      id UUID PRIMARY KEY,
      season_id UUID NOT NULL REFERENCES seasons(id) ON DELETE RESTRICT,
      match_number INTEGER NOT NULL,
      title TEXT NOT NULL,
      participant_a TEXT,
      participant_b TEXT,
      status TEXT NOT NULL DEFAULT 'SCHEDULED',
      winner TEXT,
      started_at TIMESTAMPTZ,
      completed_at TIMESTAMPTZ,
      resolved_by TEXT,
      UNIQUE (season_id, match_number),
      CHECK (status IN ('SCHEDULED','LIVE','COMPLETE','CANCELLED'))
    );
    CREATE INDEX IF NOT EXISTS season_matches_season_idx ON season_matches(season_id, match_number);
    ALTER TABLE season_matches ADD COLUMN IF NOT EXISTS format TEXT NOT NULL DEFAULT '1v1';
    ALTER TABLE season_matches ADD COLUMN IF NOT EXISTS participant_a_ids UUID[] NOT NULL DEFAULT '{}';
    ALTER TABLE season_matches ADD COLUMN IF NOT EXISTS participant_b_ids UUID[] NOT NULL DEFAULT '{}';
    ALTER TABLE season_matches ADD COLUMN IF NOT EXISTS description TEXT NOT NULL DEFAULT '';
    ALTER TABLE season_matches ADD COLUMN IF NOT EXISTS scheduled_at TIMESTAMPTZ;
    DO $$ BEGIN
      ALTER TABLE season_matches ADD CONSTRAINT season_matches_format_check CHECK (format IN ('1v1','2v2'));
    EXCEPTION WHEN duplicate_object THEN NULL; END $$;

    CREATE TABLE IF NOT EXISTS season_markets (
      id UUID PRIMARY KEY,
      season_id UUID NOT NULL REFERENCES seasons(id) ON DELETE RESTRICT,
      match_id UUID NOT NULL REFERENCES season_matches(id) ON DELETE RESTRICT,
      market_id INTEGER NOT NULL REFERENCES markets(id) ON DELETE RESTRICT,
      UNIQUE (season_id, market_id),
      UNIQUE (match_id, market_id)
    );
    CREATE INDEX IF NOT EXISTS season_markets_season_idx ON season_markets(season_id);

    CREATE TABLE IF NOT EXISTS season_results (
      id UUID PRIMARY KEY,
      season_id UUID NOT NULL REFERENCES seasons(id) ON DELETE RESTRICT,
      match_id UUID REFERENCES season_matches(id) ON DELETE RESTRICT,
      market_id INTEGER REFERENCES markets(id) ON DELETE RESTRICT,
      outcome TEXT NOT NULL,
      resolved_by TEXT NOT NULL,
      resolved_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS season_results_season_idx ON season_results(season_id, resolved_at DESC);

    CREATE TABLE IF NOT EXISTS season_stats (
      id UUID PRIMARY KEY,
      season_id UUID NOT NULL REFERENCES seasons(id) ON DELETE RESTRICT,
      account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
      predictions INTEGER NOT NULL DEFAULT 0,
      correct_predictions INTEGER NOT NULL DEFAULT 0,
      incorrect_predictions INTEGER NOT NULL DEFAULT 0,
      points_won NUMERIC(18,4) NOT NULL DEFAULT 0,
      points_lost NUMERIC(18,4) NOT NULL DEFAULT 0,
      roi NUMERIC(18,6) NOT NULL DEFAULT 0,
      accuracy NUMERIC(18,6) NOT NULL DEFAULT 0,
      current_rank INTEGER,
      UNIQUE (season_id, account_id)
    );
    CREATE INDEX IF NOT EXISTS season_stats_season_idx ON season_stats(season_id, current_rank);

    ALTER TABLE season_players ADD COLUMN IF NOT EXISTS competitive_points NUMERIC(18,4) NOT NULL DEFAULT 0;
    ALTER TABLE season_players ADD COLUMN IF NOT EXISTS matches_played INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE season_players ADD COLUMN IF NOT EXISTS wins INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE season_players ADD COLUMN IF NOT EXISTS losses INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE season_players ADD COLUMN IF NOT EXISTS tournaments_played INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE season_players ADD COLUMN IF NOT EXISTS tournament_wins INTEGER NOT NULL DEFAULT 0;

    ALTER TABLE season_matches ADD COLUMN IF NOT EXISTS round_number INTEGER NOT NULL DEFAULT 1;
    ALTER TABLE season_matches ADD COLUMN IF NOT EXISTS bracket_slot INTEGER;
    ALTER TABLE season_matches ADD COLUMN IF NOT EXISTS next_match_id UUID REFERENCES season_matches(id) ON DELETE SET NULL;
    ALTER TABLE season_matches ADD COLUMN IF NOT EXISTS next_match_side TEXT;
    ALTER TABLE season_matches ADD COLUMN IF NOT EXISTS loser_next_match_id UUID REFERENCES season_matches(id) ON DELETE SET NULL;
    ALTER TABLE season_matches ADD COLUMN IF NOT EXISTS loser_next_side TEXT;
    ALTER TABLE season_matches ADD COLUMN IF NOT EXISTS bracket_id UUID;
    ALTER TABLE season_matches ADD COLUMN IF NOT EXISTS bracket_phase TEXT NOT NULL DEFAULT 'WINNERS';
    ALTER TABLE season_matches ADD COLUMN IF NOT EXISTS source_a_match_id UUID REFERENCES season_matches(id) ON DELETE SET NULL;
    ALTER TABLE season_matches ADD COLUMN IF NOT EXISTS source_a_result TEXT;
    ALTER TABLE season_matches ADD COLUMN IF NOT EXISTS source_b_match_id UUID REFERENCES season_matches(id) ON DELETE SET NULL;
    ALTER TABLE season_matches ADD COLUMN IF NOT EXISTS source_b_result TEXT;
    ALTER TABLE season_matches ADD COLUMN IF NOT EXISTS result_recorded_at TIMESTAMPTZ;
    DO $$ BEGIN
      ALTER TABLE season_matches ADD CONSTRAINT season_matches_bracket_phase_check CHECK (bracket_phase IN ('WINNERS','LOSERS','GRAND_FINAL'));
    EXCEPTION WHEN duplicate_object THEN NULL; END $$;
    DO $$ BEGIN
      ALTER TABLE season_matches ADD CONSTRAINT season_matches_next_side_check CHECK (next_match_side IS NULL OR next_match_side IN ('A','B'));
    EXCEPTION WHEN duplicate_object THEN NULL; END $$;
    DO $$ BEGIN
      ALTER TABLE season_matches ADD CONSTRAINT season_matches_loser_next_side_check CHECK (loser_next_side IS NULL OR loser_next_side IN ('A','B'));
    EXCEPTION WHEN duplicate_object THEN NULL; END $$;
    DO $$ BEGIN
      ALTER TABLE season_matches ADD CONSTRAINT season_matches_source_a_result_check CHECK (source_a_result IS NULL OR source_a_result IN ('WINNER','LOSER'));
    EXCEPTION WHEN duplicate_object THEN NULL; END $$;
    DO $$ BEGIN
      ALTER TABLE season_matches ADD CONSTRAINT season_matches_source_b_result_check CHECK (source_b_result IS NULL OR source_b_result IN ('WINNER','LOSER'));
    EXCEPTION WHEN duplicate_object THEN NULL; END $$;
    DO $$ BEGIN
      ALTER TABLE season_matches ADD CONSTRAINT season_matches_winner_side_check CHECK (winner_side IS NULL OR winner_side IN ('A','B'));
    EXCEPTION WHEN duplicate_object THEN NULL; END $$;

    CREATE TABLE IF NOT EXISTS season_point_entries (
      id UUID PRIMARY KEY,
      season_id UUID NOT NULL REFERENCES seasons(id) ON DELETE RESTRICT,
      account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
      match_id UUID REFERENCES season_matches(id) ON DELETE RESTRICT,
      entry_type TEXT NOT NULL,
      points NUMERIC(18,4) NOT NULL,
      balance_before NUMERIC(18,4) NOT NULL,
      balance_after NUMERIC(18,4) NOT NULL,
      reference TEXT,
      details JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS season_point_entries_season_idx ON season_point_entries(season_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS season_point_entries_account_idx ON season_point_entries(account_id, season_id, created_at DESC);

    CREATE TABLE IF NOT EXISTS player_ratings (
      account_id UUID PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
      rating INTEGER NOT NULL DEFAULT 1200,
      matches_played INTEGER NOT NULL DEFAULT 0,
      wins INTEGER NOT NULL DEFAULT 0,
      losses INTEGER NOT NULL DEFAULT 0,
      peak_rating INTEGER NOT NULL DEFAULT 1200,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS rating_history (
      id UUID PRIMARY KEY,
      account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
      season_id UUID REFERENCES seasons(id) ON DELETE SET NULL,
      match_id UUID REFERENCES season_matches(id) ON DELETE SET NULL,
      rating_before INTEGER NOT NULL,
      rating_after INTEGER NOT NULL,
      delta INTEGER NOT NULL,
      opponent_rating INTEGER,
      result TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS rating_history_account_idx ON rating_history(account_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS player_ratings_rating_idx ON player_ratings(rating DESC, updated_at ASC);

    CREATE TABLE IF NOT EXISTS season_competitive_snapshots (
      season_id UUID NOT NULL REFERENCES seasons(id) ON DELETE RESTRICT,
      run_number INTEGER NOT NULL,
      account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
      rating INTEGER NOT NULL DEFAULT 1200,
      matches_played INTEGER NOT NULL DEFAULT 0,
      wins INTEGER NOT NULL DEFAULT 0,
      losses INTEGER NOT NULL DEFAULT 0,
      peak_rating INTEGER NOT NULL DEFAULT 1200,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (season_id, run_number, account_id)
    );
    CREATE INDEX IF NOT EXISTS season_competitive_snapshots_idx ON season_competitive_snapshots(season_id, run_number);
  `);

  await pool.query(`
    ALTER TABLE matches ADD COLUMN IF NOT EXISTS season_id UUID REFERENCES seasons(id) ON DELETE SET NULL;
    ALTER TABLE markets ADD COLUMN IF NOT EXISTS season_id UUID REFERENCES seasons(id) ON DELETE SET NULL;
    ALTER TABLE trades ADD COLUMN IF NOT EXISTS season_id UUID REFERENCES seasons(id) ON DELETE SET NULL;
    ALTER TABLE ledger_entries ADD COLUMN IF NOT EXISTS season_id UUID REFERENCES seasons(id) ON DELETE SET NULL;
    ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS season_id UUID REFERENCES seasons(id) ON DELETE SET NULL;
    CREATE INDEX IF NOT EXISTS matches_season_idx ON matches(season_id);
    CREATE INDEX IF NOT EXISTS markets_season_idx ON markets(season_id);
    CREATE INDEX IF NOT EXISTS trades_season_idx ON trades(season_id);
    CREATE INDEX IF NOT EXISTS ledger_entries_season_idx ON ledger_entries(season_id);
    CREATE INDEX IF NOT EXISTS audit_logs_season_idx ON audit_logs(season_id);
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS test_runs (
      id UUID PRIMARY KEY,
      status TEXT NOT NULL DEFAULT 'ACTIVE',
      label TEXT NOT NULL DEFAULT 'Ossper Demo Test',
      started_by TEXT NOT NULL,
      started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      ended_by TEXT,
      ended_at TIMESTAMPTZ,
      CHECK (status IN ('ACTIVE','ENDED'))
    );
    CREATE TABLE IF NOT EXISTS test_run_members (
      test_run_id UUID NOT NULL REFERENCES test_runs(id) ON DELETE CASCADE,
      account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
      added_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (test_run_id, account_id)
    );
    CREATE TABLE IF NOT EXISTS test_account_snapshots (
      test_run_id UUID NOT NULL REFERENCES test_runs(id) ON DELETE CASCADE,
      account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
      balance NUMERIC(18,4) NOT NULL,
      PRIMARY KEY (test_run_id, account_id)
    );
    CREATE TABLE IF NOT EXISTS test_position_snapshots (
      test_run_id UUID NOT NULL REFERENCES test_runs(id) ON DELETE CASCADE,
      account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
      market_id INTEGER NOT NULL REFERENCES markets(id) ON DELETE CASCADE,
      side TEXT NOT NULL,
      quantity INTEGER NOT NULL,
      avg_cost NUMERIC(18,6) NOT NULL,
      realized_pnl NUMERIC(18,4) NOT NULL,
      PRIMARY KEY (test_run_id, account_id, market_id, side)
    );
    CREATE TABLE IF NOT EXISTS test_market_snapshots (
      test_run_id UUID NOT NULL REFERENCES test_runs(id) ON DELETE CASCADE,
      market_id INTEGER NOT NULL REFERENCES markets(id) ON DELETE CASCADE,
      yes_price NUMERIC(10,4) NOT NULL,
      status TEXT NOT NULL,
      close_at TIMESTAMPTZ,
      result TEXT,
      PRIMARY KEY (test_run_id, market_id)
    );
    CREATE TABLE IF NOT EXISTS test_match_snapshots (
      test_run_id UUID NOT NULL REFERENCES test_runs(id) ON DELETE CASCADE,
      match_id INTEGER NOT NULL REFERENCES matches(id) ON DELETE CASCADE,
      status TEXT NOT NULL,
      PRIMARY KEY (test_run_id, match_id)
    );
  `);
  await pool.query(`CREATE TABLE IF NOT EXISTS wagers (
    id UUID PRIMARY KEY,
    market_id INTEGER NOT NULL REFERENCES markets(id) ON DELETE CASCADE,
    creator_account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    opponent_account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    creator_side TEXT NOT NULL,
    amount NUMERIC(18,4) NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING',
    winner_account_id UUID REFERENCES accounts(id) ON DELETE SET NULL,
    test_run_id UUID REFERENCES test_runs(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    accepted_at TIMESTAMPTZ,
    settled_at TIMESTAMPTZ,
    CHECK (creator_side IN ('YES','NO')),
    CHECK (amount > 0),
    CHECK (status IN ('PENDING','ACCEPTED','DECLINED','CANCELLED','SETTLED','VOID'))
  )`);
  await pool.query(`CREATE INDEX IF NOT EXISTS wagers_creator_idx ON wagers(creator_account_id, created_at DESC)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS wagers_opponent_idx ON wagers(opponent_account_id, created_at DESC)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS wagers_market_idx ON wagers(market_id, created_at DESC)`);

  await pool.query(`ALTER TABLE wagers ADD COLUMN IF NOT EXISTS test_run_id UUID REFERENCES test_runs(id) ON DELETE SET NULL`);
  await pool.query(`CREATE INDEX IF NOT EXISTS wagers_test_run_idx ON wagers(test_run_id)`);

  await pool.query("DELETE FROM sessions WHERE expires_at <= NOW()");

  // Safe migrations for databases created by v0.6.1.
  await pool.query(`ALTER TABLE admin_roles DROP CONSTRAINT IF EXISTS admin_roles_role_check`);
  await pool.query(`ALTER TABLE admin_roles ADD CONSTRAINT admin_roles_role_check CHECK (role IN ('owner','admin','moderator'))`);
  await pool.query(`ALTER TABLE matches ADD COLUMN IF NOT EXISTS test_run_id UUID REFERENCES test_runs(id) ON DELETE SET NULL`);
  await pool.query(`ALTER TABLE markets ADD COLUMN IF NOT EXISTS test_run_id UUID REFERENCES test_runs(id) ON DELETE SET NULL`);
  await pool.query(`ALTER TABLE markets ADD COLUMN IF NOT EXISTS market_type TEXT NOT NULL DEFAULT 'DYNAMIC'`);
  await pool.query(`ALTER TABLE markets ADD COLUMN IF NOT EXISTS fixed_yes_price NUMERIC(10,4)`);
  await pool.query(`ALTER TABLE markets DROP CONSTRAINT IF EXISTS markets_market_type_check`);
  await pool.query(`ALTER TABLE markets ADD CONSTRAINT markets_market_type_check CHECK (market_type IN ('DYNAMIC','FIXED'))`);
  await pool.query(`ALTER TABLE markets DROP CONSTRAINT IF EXISTS markets_fixed_yes_price_check`);
  await pool.query(`ALTER TABLE markets ADD CONSTRAINT markets_fixed_yes_price_check CHECK (fixed_yes_price IS NULL OR (fixed_yes_price >= 0.01 AND fixed_yes_price <= 0.99))`);
  await pool.query(`ALTER TABLE test_market_snapshots ADD COLUMN IF NOT EXISTS market_type TEXT`);
  await pool.query(`ALTER TABLE test_market_snapshots ADD COLUMN IF NOT EXISTS fixed_yes_price NUMERIC(10,4)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS markets_test_run_idx ON markets(test_run_id)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS matches_test_run_idx ON matches(test_run_id)`);
  await pool.query(`CREATE TABLE IF NOT EXISTS notifications (
    id BIGSERIAL PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    type TEXT NOT NULL DEFAULT 'INFO',
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    market_id INTEGER REFERENCES markets(id) ON DELETE SET NULL,
    read_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await pool.query(`ALTER TABLE notifications ADD COLUMN IF NOT EXISTS type TEXT NOT NULL DEFAULT 'INFO'`);
  await pool.query(`ALTER TABLE notifications ADD COLUMN IF NOT EXISTS title TEXT`);
  await pool.query(`ALTER TABLE notifications ADD COLUMN IF NOT EXISTS message TEXT`);
  await pool.query(`ALTER TABLE notifications ADD COLUMN IF NOT EXISTS market_id INTEGER`);
  await pool.query(`ALTER TABLE notifications ADD COLUMN IF NOT EXISTS read_at TIMESTAMPTZ`);
  await pool.query(`ALTER TABLE notifications ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`);
  await pool.query(`CREATE INDEX IF NOT EXISTS notifications_account_created_idx ON notifications(account_id, created_at DESC)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS notifications_unread_idx ON notifications(account_id, read_at)`);
  await pool.query(`ALTER TABLE markets ADD COLUMN IF NOT EXISTS match_id INTEGER REFERENCES matches(id) ON DELETE SET NULL`);
  await pool.query(`ALTER TABLE trades ADD COLUMN IF NOT EXISTS test_run_id UUID REFERENCES test_runs(id) ON DELETE SET NULL`);
  await pool.query(`ALTER TABLE ledger_entries ADD COLUMN IF NOT EXISTS test_run_id UUID REFERENCES test_runs(id) ON DELETE SET NULL`);
  await pool.query(`ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS test_run_id UUID REFERENCES test_runs(id) ON DELETE SET NULL`);
  await pool.query(`CREATE INDEX IF NOT EXISTS trades_test_run_idx ON trades(test_run_id)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS audit_test_run_idx ON audit_logs(test_run_id)`);
  await pool.query(`ALTER TABLE markets ADD COLUMN IF NOT EXISTS opening_yes_price NUMERIC(10,4) NOT NULL DEFAULT 0.50`);
  await pool.query(`ALTER TABLE markets ADD COLUMN IF NOT EXISTS liquidity NUMERIC(18,4) NOT NULL DEFAULT 100.00`);
  await pool.query(`ALTER TABLE accounts ADD COLUMN IF NOT EXISTS discord_id TEXT`);
  await pool.query(`ALTER TABLE accounts ADD COLUMN IF NOT EXISTS display_name TEXT`);
  await pool.query(`ALTER TABLE accounts ADD COLUMN IF NOT EXISTS avatar_url TEXT`);
  await pool.query(`ALTER TABLE accounts ADD COLUMN IF NOT EXISTS auth_provider TEXT NOT NULL DEFAULT 'guest'`);
  await pool.query(`ALTER TABLE accounts ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ`);
  await pool.query(`ALTER TABLE accounts ADD COLUMN IF NOT EXISTS test_roster_key TEXT`);
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS accounts_test_roster_key_idx ON accounts(test_roster_key) WHERE test_roster_key IS NOT NULL`);
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

async function getActiveTestRun() {
  const q = await pool.query("SELECT * FROM test_runs WHERE status='ACTIVE' ORDER BY started_at DESC LIMIT 1");
  return q.rows[0] || null;
}

async function getActiveTestForAccount(accountId) {
  const q = await pool.query(`
    SELECT tr.* FROM test_runs tr
    JOIN test_run_members m ON m.test_run_id=tr.id AND m.account_id=$1
    WHERE tr.status='ACTIVE' ORDER BY tr.started_at DESC LIMIT 1
  `, [accountId]);
  return q.rows[0] || null;
}

async function assertTestParticipant(accountId) {
  const active = await getActiveTestRun();
  if (!active) return null;
  const q = await pool.query("SELECT 1 FROM test_run_members WHERE test_run_id=$1 AND account_id=$2", [active.id, accountId]);
  if (!q.rows.length) throw new Error("A controlled Ossper test is active. Your account is not enrolled in this test.");
  return active;
}

async function testAudit(actor, action, details, testRunId = null, marketId = null) {
  await pool.query(`INSERT INTO audit_logs (actor, action, market_id, details, test_run_id) VALUES ($1,$2,$3,$4,$5)`, [actor, action, marketId, JSON.stringify(details || {}), testRunId]);
}

async function snapshotTestState(client, runId, memberIds) {
  const markets = await client.query("SELECT id, yes_price, status, close_at, result FROM markets");
  for (const m of markets.rows) {
    await client.query(`INSERT INTO test_market_snapshots (test_run_id, market_id, yes_price, status, close_at, result, market_type, fixed_yes_price) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, [runId, m.id, m.yes_price, m.status, m.close_at, m.result, m.market_type || 'DYNAMIC', m.fixed_yes_price]);
  }
  const matches = await client.query("SELECT id, status FROM matches");
  for (const m of matches.rows) {
    await client.query(`INSERT INTO test_match_snapshots (test_run_id, match_id, status) VALUES ($1,$2,$3)`, [runId, m.id, m.status]);
  }
  for (const accountId of memberIds) {
    const a = await client.query("SELECT balance FROM accounts WHERE id=$1 FOR UPDATE", [accountId]);
    if (!a.rows.length) throw new Error(`Account ${accountId} not found.`);
    await client.query(`INSERT INTO test_account_snapshots (test_run_id, account_id, balance) VALUES ($1,$2,$3)`, [runId, accountId, a.rows[0].balance]);
    const positions = await client.query("SELECT market_id, side, quantity, avg_cost, realized_pnl FROM positions WHERE account_id=$1", [accountId]);
    for (const p of positions.rows) {
      await client.query(`INSERT INTO test_position_snapshots (test_run_id, account_id, market_id, side, quantity, avg_cost, realized_pnl) VALUES ($1,$2,$3,$4,$5,$6,$7)`, [runId, accountId, p.market_id, p.side, p.quantity, p.avg_cost, p.realized_pnl]);
    }
  }
}

async function restoreTestState(client, runId) {
  const members = await client.query("SELECT account_id FROM test_run_members WHERE test_run_id=$1", [runId]);
  for (const row of members.rows) {
    const snap = await client.query("SELECT balance FROM test_account_snapshots WHERE test_run_id=$1 AND account_id=$2", [runId, row.account_id]);
    const current = await client.query("SELECT balance FROM accounts WHERE id=$1 FOR UPDATE", [row.account_id]);
    if (snap.rows.length && current.rows.length) {
      const before = Number(current.rows[0].balance);
      const after = Number(snap.rows[0].balance);
      await client.query("UPDATE accounts SET balance=$1 WHERE id=$2", [after, row.account_id]);
      if (Math.abs(before-after) > 0.00005) {
        await client.query(`INSERT INTO ledger_entries (account_id, entry_type, amount, balance_before, balance_after, reference, details, test_run_id) VALUES ($1,'TEST_END_RESTORE',$2,$3,$4,$5,$6,$7)`, [row.account_id, Number((after-before).toFixed(4)), before, after, `TEST_END_${runId}`, JSON.stringify({testRunId:runId}), runId]);
      }
    }
    await client.query("DELETE FROM positions WHERE account_id=$1", [row.account_id]);
    const ps = await client.query("SELECT market_id, side, quantity, avg_cost, realized_pnl FROM test_position_snapshots WHERE test_run_id=$1 AND account_id=$2", [runId, row.account_id]);
    for (const p of ps.rows) {
      await client.query(`INSERT INTO positions (account_id, market_id, side, quantity, avg_cost, realized_pnl) VALUES ($1,$2,$3,$4,$5,$6)`, [row.account_id, p.market_id, p.side, p.quantity, p.avg_cost, p.realized_pnl]);
    }
  }
  const markets = await client.query("SELECT market_id, yes_price, status, close_at, result FROM test_market_snapshots WHERE test_run_id=$1", [runId]);
  for (const m of markets.rows) {
    await client.query("UPDATE markets SET yes_price=$1,status=$2,close_at=$3,result=$4,market_type=COALESCE($5,'DYNAMIC'),fixed_yes_price=$6,updated_at=NOW() WHERE id=$7", [m.yes_price,m.status,m.close_at,m.result,m.market_type,m.fixed_yes_price,m.market_id]);
  }
  const matches = await client.query("SELECT match_id,status FROM test_match_snapshots WHERE test_run_id=$1", [runId]);
  for (const m of matches.rows) await client.query("UPDATE matches SET status=$1,updated_at=NOW() WHERE id=$2", [m.status,m.match_id]);
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

async function createNotification(client, { accountId, type = 'INFO', title, message, marketId = null }) {
  await client.query(
    `INSERT INTO notifications (account_id, type, title, message, market_id) VALUES ($1,$2,$3,$4,$5)`,
    [accountId, type, String(title).slice(0, 180), String(message).slice(0, 1000), marketId]
  );
}

async function addLedgerEntry(client, { accountId, entryType, amount, balanceBefore, balanceAfter, marketId = null, tradeId = null, reference = null, details = {}, testRunId = null }) {
  await client.query(`
    INSERT INTO ledger_entries (account_id, entry_type, amount, balance_before, balance_after, market_id, trade_id, reference, details, test_run_id)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
  `, [accountId, entryType, amount, balanceBefore, balanceAfter, marketId, tradeId, reference, JSON.stringify(details), testRunId]);
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
  const activeTest = await getActiveTestForAccount(accountId);
  if (!activeTest) {
    const anyActive = await getActiveTestRun();
    if (anyActive) {
      const base = await pool.query("SELECT yes_price,status,close_at,result FROM test_market_snapshots WHERE test_run_id=$1 AND market_id=$2", [anyActive.id, marketId]);
      if (base.rows.length) Object.assign(market, base.rows[0]);
    }
  }

  const positionsQ = await pool.query(
    "SELECT side, quantity, avg_cost, realized_pnl FROM positions WHERE account_id=$1 AND market_id=$2 AND quantity > 0 ORDER BY side",
    [accountId, marketId]
  );

  const tradesQ = activeTest
    ? await pool.query("SELECT action, side, quantity, price, gross, fee, created_at FROM trades WHERE account_id=$1 AND market_id=$2 AND test_run_id=$3 ORDER BY id DESC LIMIT 30", [accountId, marketId, activeTest.id])
    : await pool.query("SELECT action, side, quantity, price, gross, fee, created_at FROM trades WHERE account_id=$1 AND market_id=$2 AND test_run_id IS NULL ORDER BY id DESC LIMIT 30", [accountId, marketId]);

  const volumeQ = activeTest
    ? await pool.query("SELECT COALESCE(SUM(gross),0) AS volume FROM trades WHERE market_id=$1 AND test_run_id=$2", [marketId, activeTest.id])
    : await pool.query("SELECT COALESCE(SUM(gross),0) AS volume FROM trades WHERE market_id=$1 AND test_run_id IS NULL", [marketId]);
  if (activeTest) {
    const base = await pool.query("SELECT yes_price,status,close_at,result FROM test_market_snapshots WHERE test_run_id=$1 AND market_id=$2", [activeTest.id, marketId]);
    if (base.rows.length && !activeTest) { /* unreachable; kept intentionally simple */ }
  }

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
  const yes = Number(market.market_type === 'FIXED' && market.fixed_yes_price != null ? market.fixed_yes_price : market.yes_price);
  const endYes = market.market_type === 'FIXED'
    ? yes
    : projectPrice(yes, market.liquidity, side, action, quantity);
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
    const controlQ = await client.query("SELECT frozen, reason FROM system_controls WHERE id=1 FOR UPDATE");
    if (controlQ.rows[0]?.frozen) throw new Error(`Ossper is frozen by administration${controlQ.rows[0].reason ? `: ${controlQ.rows[0].reason}` : '.'}`);
    const m = await client.query("SELECT * FROM markets WHERE id=$1 FOR UPDATE", [marketId]);
    if (!m.rows.length) throw new Error("Market not found.");
    const market = m.rows[0];
    if (!["OPEN","TRADING"].includes(market.status)) throw new Error("Trading is closed for this market.");
    if (market.close_at && new Date(market.close_at).getTime() <= Date.now()) {
      await client.query("UPDATE markets SET status='CLOSED', updated_at=NOW() WHERE id=$1", [marketId]);
      throw new Error("Trading has closed for this market.");
    }

    const accountQ = await client.query("SELECT * FROM accounts WHERE id=$1 FOR UPDATE", [accountId]);
    if (!accountQ.rows.length) throw new Error("Account not found.");
    const account = accountQ.rows[0];
    const activeTestQ = await client.query(`SELECT tr.id FROM test_runs tr JOIN test_run_members tm ON tm.test_run_id=tr.id AND tm.account_id=$1 WHERE tr.status='ACTIVE' ORDER BY tr.started_at DESC LIMIT 1`, [accountId]);
    const testRunId = activeTestQ.rows[0]?.id || null;
    const anyActiveQ = await client.query("SELECT id FROM test_runs WHERE status='ACTIVE' ORDER BY started_at DESC LIMIT 1");
    if (anyActiveQ.rows.length && !testRunId) throw new Error("A controlled Ossper test is active. Your account is not enrolled in this test.");

    const quote = quoteForMarket(market, side, action, quantity);
    const price = quote.averagePrice;
    const gross = quote.gross;
    const fee = quote.fee;

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
      const balanceBefore = Number(account.balance);
      const balanceAfter = Number((balanceBefore - totalDebit).toFixed(4));
      await client.query("UPDATE accounts SET balance = $1 WHERE id=$2", [balanceAfter, accountId]);
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
      const balanceBefore = Number(account.balance);
      const balanceAfter = Number((balanceBefore + netCredit).toFixed(4));
      await client.query("UPDATE accounts SET balance = $1 WHERE id=$2", [balanceAfter, accountId]);
      await client.query(`
        INSERT INTO positions (account_id, market_id, side, quantity, avg_cost, realized_pnl)
        VALUES ($1,$2,$3,$4,$5,$6)
        ON CONFLICT (account_id, market_id, side)
        DO UPDATE SET quantity=EXCLUDED.quantity, avg_cost=EXCLUDED.avg_cost, realized_pnl=positions.realized_pnl + EXCLUDED.realized_pnl
      `, [accountId, marketId, side, newQty, newQty ? currentAvg : 0, realized]);
    }

    const nextYes = quote.yesPriceAfter;
    await client.query("UPDATE markets SET yes_price=$1, updated_at=NOW() WHERE id=$2", [nextYes, marketId]);

    const tradeQ = await client.query(`
      INSERT INTO trades (account_id, market_id, side, action, quantity, price, gross, fee, test_run_id)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
      RETURNING id
    `, [accountId, marketId, side, action, quantity, price, gross, fee, testRunId]);

    const ledgerAmount = action === 'BUY' ? -Number((gross + fee).toFixed(4)) : Number((gross - fee).toFixed(4));
    const balanceBeforeForLedger = Number(account.balance);
    const balanceAfterForLedger = action === 'BUY'
      ? Number((balanceBeforeForLedger + ledgerAmount).toFixed(4))
      : Number((balanceBeforeForLedger + ledgerAmount).toFixed(4));
    await addLedgerEntry(client, {
      accountId, entryType: action === 'BUY' ? 'TRADE_DEBIT' : 'TRADE_CREDIT',
      amount: ledgerAmount, balanceBefore: balanceBeforeForLedger, balanceAfter: balanceAfterForLedger,
      marketId, tradeId: tradeQ.rows[0].id, reference: `${action}_${side}`,
      details: { side, quantity, price, gross, fee }, testRunId
    });

    await client.query(`
      INSERT INTO audit_logs (actor, action, market_id, details, test_run_id)
      VALUES ($1,$2,$3,$4,$5)
    `, [accountId, `${action}_${side}`, marketId, JSON.stringify({ quantity, price, gross, fee, priceMove: quote.priceMove, yesPriceAfter: quote.yesPriceAfter, liquidity: Number(market.liquidity) }), testRunId]);

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
  // The OAuth state is signed and self-contained. Mobile browsers can drop the
  // temporary state cookie during the Discord handoff, so the callback must not
  // require that cookie to complete a valid login.
  const state = readAuthState(req.query.state);
  const cookieState = readAuthState(cookieValue(req, "ossper_oauth_state"));
  if (!state) return res.status(400).send("Discord login state expired or invalid. Please try again.");
  if (cookieState && cookieState.nonce !== state.nonce) return res.status(400).send("Discord login state mismatch. Please start login again.");
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
      } else if (cookieState?.accountId) {
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
  }
}

app.get("/api/market/:id/chart", async (req, res) => {
  try {
    const accountId = await requestAccountId(req);
    if (!accountId) return res.status(400).json({ error: "Missing account." });
    await ensureAccount(accountId);
    const marketId = Number(req.params.id);
    const mQ = await pool.query("SELECT * FROM markets WHERE id=$1", [marketId]);
    if (!mQ.rows.length) return res.status(404).json({ error: "Market not found." });
    const market = mQ.rows[0];
    const activeTest = await getActiveTestForAccount(accountId);
    if (market.test_run_id) {
      if (!activeTest || String(market.test_run_id) !== String(activeTest.id)) return res.status(404).json({ error: "Market not found." });
    } else if (activeTest) {
      // Production markets remain visible inside a controlled test, but their history is kept on the production stream.
    }
    const testRunId = market.test_run_id || null;
    const tradeQ = testRunId
      ? await pool.query(`SELECT price, side, quantity, gross, created_at FROM trades WHERE market_id=$1 AND test_run_id=$2 ORDER BY id ASC LIMIT 500`, [marketId, testRunId])
      : await pool.query(`SELECT price, side, quantity, gross, created_at FROM trades WHERE market_id=$1 AND test_run_id IS NULL ORDER BY id ASC LIMIT 500`, [marketId]);
    const opening = Number(market.market_type === 'FIXED' && market.fixed_yes_price != null ? market.fixed_yes_price : market.opening_yes_price || market.yes_price);
    let cumulative = 0;
    const points = [{ t: market.created_at, yes: Number(opening.toFixed(4)), volume: 0 }];
    for (const t of tradeQ.rows) {
      const sidePrice = Number(t.price);
      const yes = t.side === 'YES' ? sidePrice : 1 - sidePrice;
      cumulative += Number(t.gross || 0);
      points.push({ t: t.created_at, yes: Number(yes.toFixed(4)), volume: Number(cumulative.toFixed(4)) });
    }
    const currentYes = Number(market.market_type === 'FIXED' && market.fixed_yes_price != null ? market.fixed_yes_price : market.yes_price);
    if (!points.length || points[points.length - 1].yes !== Number(currentYes.toFixed(4))) {
      points.push({ t: market.updated_at || new Date().toISOString(), yes: Number(currentYes.toFixed(4)), volume: Number(cumulative.toFixed(4)) });
    }
    res.set('Cache-Control','no-store');
    res.json({ marketId, question: market.question, openingYes: opening, currentYes, points, tradeCount: tradeQ.rowCount });
  } catch (e) {
    res.status(500).json({ error: "Unable to load market chart." });
  }
});

app.get("/api/portfolio/chart", async (req, res) => {
  try {
    const accountId = await requestAccountId(req);
    if (!accountId) return res.status(400).json({ error: "Missing account." });
    await ensureAccount(accountId);
    const activeTest = await getActiveTestForAccount(accountId);
    const testRunId = activeTest?.id || null;
    const tradeWhere = testRunId ? "t.test_run_id=$1" : "t.test_run_id IS NULL";
    const tradeParams = testRunId ? [testRunId, accountId] : [accountId];
    const accountTradeSql = testRunId
      ? `SELECT t.id,t.market_id,t.side,t.action,t.quantity,t.price,t.gross,t.fee,t.created_at,le.balance_after
         FROM trades t LEFT JOIN ledger_entries le ON le.trade_id=t.id AND le.account_id=t.account_id AND le.test_run_id=t.test_run_id
         WHERE t.account_id=$2 AND t.test_run_id=$1 ORDER BY t.created_at ASC,t.id ASC LIMIT 1000`
      : `SELECT t.id,t.market_id,t.side,t.action,t.quantity,t.price,t.gross,t.fee,t.created_at,le.balance_after
         FROM trades t LEFT JOIN ledger_entries le ON le.trade_id=t.id AND le.account_id=t.account_id AND le.test_run_id IS NULL
         WHERE t.account_id=$1 AND t.test_run_id IS NULL ORDER BY t.created_at ASC,t.id ASC LIMIT 1000`;
    const accountTradesQ = await pool.query(accountTradeSql, tradeParams);
    const currentAccountQ = await pool.query('SELECT balance FROM accounts WHERE id=$1',[accountId]);
    const currentBalance=Number(currentAccountQ.rows[0]?.balance ?? 500);
    const positionsQ=await pool.query(`SELECT p.market_id,p.side,p.quantity,p.avg_cost,m.yes_price FROM positions p JOIN markets m ON m.id=p.market_id WHERE p.account_id=$1 AND p.quantity>0`,[accountId]);
    const currentEquity=currentBalance+positionsQ.rows.reduce((sum,p)=>sum+Number(p.quantity)*(p.side==='YES'?Number(p.yes_price):1-Number(p.yes_price)),0);
    if(!accountTradesQ.rows.length){
      const now=new Date().toISOString();
      return res.json({points:[{t:now,equity:Number(currentEquity.toFixed(4)),event:'Current account equity'}],currentBalance:Number(currentBalance.toFixed(4)),currentEquity:Number(currentEquity.toFixed(4))});
    }
    const marketIds=[...new Set(accountTradesQ.rows.map(t=>Number(t.market_id)))];
    const marketsQ=await pool.query(`SELECT id,opening_yes_price,yes_price FROM markets WHERE id=ANY($1::int[])`,[marketIds]);
    const yesPrices=new Map(marketsQ.rows.map(m=>[Number(m.id),Number(m.opening_yes_price ?? m.yes_price ?? .5)]));
    const globalTradeSql=testRunId
      ? `SELECT market_id,side,price,created_at,id FROM trades WHERE test_run_id=$1 AND market_id=ANY($2::int[]) ORDER BY created_at ASC,id ASC LIMIT 10000`
      : `SELECT market_id,side,price,created_at,id FROM trades WHERE test_run_id IS NULL AND market_id=ANY($1::int[]) ORDER BY created_at ASC,id ASC LIMIT 10000`;
    const globalParams=testRunId?[testRunId,marketIds]:[marketIds];
    const globalTradesQ=await pool.query(globalTradeSql,globalParams);
    const positions=new Map(),points=[];let gi=0;const globals=globalTradesQ.rows;
    for(const t of accountTradesQ.rows){
      const at=new Date(t.created_at).getTime();
      while(gi<globals.length && new Date(globals[gi].created_at).getTime()<=at){const gt=globals[gi++],gp=Number(gt.price);yesPrices.set(Number(gt.market_id),gt.side==='YES'?gp:1-gp)}
      const marketId=Number(t.market_id),qty=Number(t.quantity),price=Number(t.price),key=`${marketId}:${t.side}`;
      const nextQty=Math.max(0,Number(positions.get(key)||0)+(t.action==='BUY'?qty:-qty));
      if(nextQty)positions.set(key,nextQty);else positions.delete(key);
      yesPrices.set(marketId,t.side==='YES'?price:1-price);
      const cash=Number(t.balance_after!=null?t.balance_after:currentBalance);
      let equity=cash;
      for(const [k,q] of positions){const [mid,side]=k.split(':');const yp=Number(yesPrices.get(Number(mid))??.5);equity+=q*(side==='YES'?yp:1-yp)}
      points.push({t:t.created_at,equity:Number(equity.toFixed(4)),event:`${t.action} ${t.side} · ${qty} contracts`});
    }
    const now=new Date().toISOString();
    points.push({t:now,equity:Number(currentEquity.toFixed(4)),event:'Current account equity'});
    res.set('Cache-Control','no-store');
    res.json({points,currentBalance:Number(currentBalance.toFixed(4)),currentEquity:Number(currentEquity.toFixed(4))});
  } catch (e) {
    console.error('portfolio chart', e);
    res.status(500).json({ error: "Unable to load portfolio chart." });
  }
});
app.get("/api/wagers/users", async (req, res) => {
  try {
    const accountId = await requestAccountId(req);
    if (!accountId) return res.status(400).json({ error: "Missing account." });
    await ensureAccount(accountId);
    const q = String(req.query.q || '').trim().slice(0, 80);
    if (q.length < 2) return res.json({ users: [] });
    const activeTest = await getActiveTestForAccount(accountId);
    const params = [`%${q}%`, accountId];
    let sql = `SELECT a.id, a.discord_id, a.display_name FROM accounts a WHERE a.id <> $2 AND (a.display_name ILIKE $1 OR a.discord_id ILIKE $1)`;
    if (activeTest) {
      params.push(activeTest.id);
      sql += ` AND EXISTS (SELECT 1 FROM test_run_members tm WHERE tm.test_run_id=$3 AND tm.account_id=a.id)`;
    }
    sql += ` ORDER BY LOWER(COALESCE(a.display_name,'')), a.discord_id LIMIT 15`;
    const rows = await pool.query(sql, params);
    res.set('Cache-Control','no-store');
    res.json({ users: rows.rows });
  } catch (e) {
    res.status(500).json({ error: "Unable to search players." });
  }
});

app.get("/api/wagers", async (req, res) => {
  try {
    const accountId = await requestAccountId(req);
    if (!accountId) return res.status(400).json({ error: "Missing account." });
    await ensureAccount(accountId);
    const q = await pool.query(`
      SELECT w.*, m.question, m.result, m.status AS market_status,
        c.display_name AS creator_name, c.discord_id AS creator_discord_id,
        o.display_name AS opponent_name, o.discord_id AS opponent_discord_id,
        win.display_name AS winner_name
      FROM wagers w
      JOIN markets m ON m.id=w.market_id
      JOIN accounts c ON c.id=w.creator_account_id
      JOIN accounts o ON o.id=w.opponent_account_id
      LEFT JOIN accounts win ON win.id=w.winner_account_id
      WHERE w.creator_account_id=$1 OR w.opponent_account_id=$1
      ORDER BY w.created_at DESC LIMIT 100`, [accountId]);
    res.set('Cache-Control','no-store');
    res.json({ wagers: q.rows.map(w => ({
      ...w, amount:Number(w.amount), isCreator:String(w.creator_account_id)===String(accountId)
    })) });
  } catch (e) { res.status(500).json({ error: "Unable to load wagers." }); }
});

app.post("/api/wagers", async (req, res) => {
  try {
    await assertSystemActive();
    const accountId = await requestAccountId(req);
    if (!accountId) return res.status(400).json({ error: "Missing account." });
    await ensureAccount(accountId);
    const marketId = Number(req.body?.marketId);
    const opponentId = String(req.body?.opponentId || '').trim();
    const side = String(req.body?.side || '').toUpperCase();
    const amount = Number(req.body?.amount);
    if (!Number.isInteger(marketId) || marketId < 1) throw new Error('Choose a market.');
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(opponentId)) throw new Error('Choose a valid opponent.');
    if (String(accountId).toLowerCase() === opponentId.toLowerCase()) throw new Error('You cannot wager against yourself.');
    if (!['YES','NO'].includes(side)) throw new Error('Choose YES or NO.');
    if (!Number.isFinite(amount) || amount < 1 || amount > 100000) throw new Error('Wager must be between $1 and $100,000.');
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const mQ = await client.query('SELECT * FROM markets WHERE id=$1 FOR UPDATE', [marketId]);
      if (!mQ.rows.length) throw new Error('Market not found.');
      const market = mQ.rows[0];
      if (market.market_type === 'MULTI') throw new Error('Head-to-head wagers currently support YES/NO markets only.');
      if (!['OPEN','TRADING'].includes(market.status)) throw new Error('Wagers close when market trading closes.');
      const opponentQ = await client.query('SELECT id,display_name,discord_id FROM accounts WHERE id=$1 FOR UPDATE', [opponentId]);
      if (!opponentQ.rows.length) throw new Error('Opponent account not found.');
      const activeQ = await client.query(`SELECT id FROM test_runs WHERE status='ACTIVE' ORDER BY started_at DESC LIMIT 1`);
      const testRunId = activeQ.rows[0]?.id || null;
      if (testRunId) {
        const members = await client.query('SELECT account_id FROM test_run_members WHERE test_run_id=$1 AND account_id=ANY($2::uuid[])',[testRunId,[accountId,opponentId]]);
        if (members.rowCount !== 2) throw new Error('Both players must be enrolled in the active controlled test.');
      }
      const acctQ = await client.query('SELECT balance FROM accounts WHERE id=$1 FOR UPDATE',[accountId]);
      const balanceBefore = Number(acctQ.rows[0].balance);
      if (balanceBefore + 1e-9 < amount) throw new Error('Insufficient balance to lock this wager.');
      const balanceAfter = Number((balanceBefore - amount).toFixed(4));
      await client.query('UPDATE accounts SET balance=$1 WHERE id=$2',[balanceAfter,accountId]);
      const wagerId = crypto.randomUUID();
      await client.query(`INSERT INTO wagers(id,market_id,creator_account_id,opponent_account_id,creator_side,amount,status,test_run_id) VALUES($1,$2,$3,$4,$5,$6,'PENDING',$7)`,[wagerId,marketId,accountId,opponentId,side,amount,testRunId]);
      await addLedgerEntry(client,{accountId,entryType:'WAGER_ESCROW',amount:-amount,balanceBefore,balanceAfter,marketId,reference:`WAGER_${wagerId}`,details:{wagerId,side,amount},testRunId});
      await createNotification(client,{accountId:opponentId,type:'WAGER',title:'New Ossper wager',message:`You were challenged to a ${side} wager for $${amount.toFixed(2)} on ${market.question}.`,marketId});
      await client.query(`INSERT INTO audit_logs(actor,action,market_id,details,test_run_id) VALUES($1,'WAGER_CREATED',$2,$3,$4)`,[accountId,marketId,JSON.stringify({wagerId,opponentId,side,amount}),testRunId]);
      await client.query('COMMIT');
      res.json({ok:true,wagerId});
    } catch(e) { await client.query('ROLLBACK'); throw e; } finally { client.release(); }
  } catch(e) { res.status(400).json({error:e.message}); }
});

app.post("/api/wagers/:id/accept", async (req,res) => {
  try {
    await assertSystemActive();
    const accountId=await requestAccountId(req); if(!accountId)return res.status(400).json({error:'Missing account.'});
    const client=await pool.connect();
    try{
      await client.query('BEGIN');
      const q=await client.query('SELECT w.*,m.question,m.status AS market_status FROM wagers w JOIN markets m ON m.id=w.market_id WHERE w.id=$1 FOR UPDATE',[req.params.id]);
      if(!q.rows.length)throw new Error('Wager not found.'); const w=q.rows[0];
      if(String(w.opponent_account_id)!==String(accountId))throw new Error('Only the challenged player can accept this wager.');
      if(w.status!=='PENDING')throw new Error('This wager is no longer pending.');
      if(!['OPEN','TRADING'].includes(w.market_status))throw new Error('This market is no longer accepting wagers.');
      const acct=await client.query('SELECT balance FROM accounts WHERE id=$1 FOR UPDATE',[accountId]); const before=Number(acct.rows[0].balance); const amount=Number(w.amount); if(before+1e-9<amount)throw new Error('Insufficient balance to accept this wager.'); const after=Number((before-amount).toFixed(4));
      await client.query('UPDATE accounts SET balance=$1 WHERE id=$2',[after,accountId]);
      await client.query("UPDATE wagers SET status='ACCEPTED',accepted_at=NOW() WHERE id=$1",[w.id]);
      await addLedgerEntry(client,{accountId,entryType:'WAGER_ESCROW',amount:-amount,balanceBefore:before,balanceAfter:after,marketId:w.market_id,reference:`WAGER_${w.id}`,details:{wagerId:w.id,side:w.creator_side==='YES'?'NO':'YES',amount},testRunId:w.test_run_id});
      await createNotification(client,{accountId:w.creator_account_id,type:'WAGER',title:'Wager accepted',message:`Your $${amount.toFixed(2)} wager on ${w.question} was accepted.`,marketId:w.market_id});
      await client.query(`INSERT INTO audit_logs(actor,action,market_id,details,test_run_id) VALUES($1,'WAGER_ACCEPTED',$2,$3,$4)`,[accountId,w.market_id,JSON.stringify({wagerId:w.id,amount}),w.test_run_id]);
      await client.query('COMMIT'); res.json({ok:true});
    }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
  }catch(e){res.status(400).json({error:e.message})}
});

async function cancelOrDeclineWager(req,res,mode){
  try{
    await assertSystemActive(); const accountId=await requestAccountId(req); if(!accountId)return res.status(400).json({error:'Missing account.'});
    const client=await pool.connect(); try{
      await client.query('BEGIN'); const q=await client.query('SELECT * FROM wagers WHERE id=$1 FOR UPDATE',[req.params.id]); if(!q.rows.length)throw new Error('Wager not found.'); const w=q.rows[0];
      const allowed=mode==='CANCEL'?String(w.creator_account_id)===String(accountId):String(w.opponent_account_id)===String(accountId); if(!allowed)throw new Error(`Only the ${mode==='CANCEL'?'creator':'challenged player'} can ${mode.toLowerCase()} this wager.`); if(w.status!=='PENDING')throw new Error('This wager is no longer pending.');
      const targetStatus=mode==='CANCEL'?'CANCELLED':'DECLINED'; const acct=await client.query('SELECT balance FROM accounts WHERE id=$1 FOR UPDATE',[w.creator_account_id]); const before=Number(acct.rows[0].balance); const after=Number((before+Number(w.amount)).toFixed(4)); await client.query('UPDATE accounts SET balance=$1 WHERE id=$2',[after,w.creator_account_id]);
      await client.query('UPDATE wagers SET status=$1,settled_at=NOW() WHERE id=$2',[targetStatus,w.id]);
      await addLedgerEntry(client,{accountId:w.creator_account_id,entryType:'WAGER_REFUND',amount:Number(w.amount),balanceBefore:before,balanceAfter:after,marketId:w.market_id,reference:`WAGER_${w.id}`,details:{wagerId:w.id,status:targetStatus},testRunId:w.test_run_id});
      await client.query('COMMIT');res.json({ok:true});
    }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
  }catch(e){res.status(400).json({error:e.message})}
}
app.post("/api/wagers/:id/decline",(req,res)=>cancelOrDeclineWager(req,res,'DECLINE'));
app.post("/api/wagers/:id/cancel",(req,res)=>cancelOrDeclineWager(req,res,'CANCEL'));

app.get("/api/markets", async (req, res) => {
  const accountId = await requestAccountId(req);
  if (!accountId) return res.status(400).json({ error: "Missing account." });
  await ensureAccount(accountId);
  await closeExpiredMarkets();
  const activeTest = await getActiveTestForAccount(accountId);
  const where = activeTest
    ? "status <> 'DRAFT' AND (test_run_id IS NULL OR test_run_id=$1)"
    : "status <> 'DRAFT' AND test_run_id IS NULL";
  const params = activeTest ? [activeTest.id] : [];
  const q = await pool.query(`SELECT * FROM markets WHERE ${where} ORDER BY id DESC`, params);
  const out = [];
  for (const m of q.rows) {
    const snap = await marketSnapshot(m.id, accountId);
    if (snap) out.push(snap);
  }
  res.set("Cache-Control", "no-store");
  res.json(out);
});

app.get("/api/market/:id", async (req, res) => {
  const accountId = await requestAccountId(req);
  if (!accountId) return res.status(400).json({ error: "Missing account." });
  await ensureAccount(accountId);
  const snap = await marketSnapshot(Number(req.params.id), accountId);
  if (!snap) return res.status(404).json({ error: "Market not found." });
  const activeTest = await getActiveTestForAccount(accountId);
  if (snap.market.test_run_id && (!activeTest || String(snap.market.test_run_id) !== String(activeTest.id))) {
    return res.status(404).json({ error: "Market not found." });
  }
  res.set("Cache-Control", "no-store");
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
    if (!["YES","NO"].includes(side) || !["BUY","SELL"].includes(action)) throw new Error("Invalid quote.");
    const q = await pool.query("SELECT * FROM markets WHERE id=$1", [marketId]);
    if (!q.rows.length) return res.status(404).json({ error: "Market not found." });
    const market = q.rows[0];
    if (!["OPEN","TRADING"].includes(market.status)) throw new Error("Trading is closed for this market.");
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

app.get("/api/system", async (_req, res) => {
  const control = await getSystemControl();
  res.json({ frozen: Boolean(control.frozen), reason: control.reason || '', changedAt: control.changed_at });
});

app.get("/api/notifications", async (req, res) => {
  const accountId = await requestAccountId(req);
  if (!accountId) return res.json({ notifications: [], unread: 0 });
  const q = await pool.query(
    `SELECT id, type, title, message, market_id, read_at, created_at
     FROM notifications WHERE account_id=$1 ORDER BY created_at DESC LIMIT 50`,
    [accountId]
  );
  const unread = q.rows.filter(n => !n.read_at).length;
  res.set("Cache-Control", "no-store");
  res.json({ notifications: q.rows, unread });
});
app.post("/api/notifications/:id/read", async (req, res) => {
  const accountId = await requestAccountId(req);
  if (!accountId) return res.status(401).json({ error: "Missing account." });
  await pool.query("UPDATE notifications SET read_at=COALESCE(read_at,NOW()) WHERE id=$1 AND account_id=$2", [Number(req.params.id), accountId]);
  res.json({ ok: true });
});
app.post("/api/notifications/read-all", async (req, res) => {
  const accountId = await requestAccountId(req);
  if (!accountId) return res.status(401).json({ error: "Missing account." });
  await pool.query("UPDATE notifications SET read_at=NOW() WHERE account_id=$1 AND read_at IS NULL", [accountId]);
  res.json({ ok: true });
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

app.get("/api/admin/users", adminOnly, async (req, res) => {
  const q = String(req.query.q || "").trim().slice(0, 80);
  const params = [];
  let where = "WHERE discord_id IS NOT NULL";
  if (q) {
    params.push(`%${q}%`);
    where += " AND (display_name ILIKE $1 OR discord_id ILIKE $1)";
  }
  const rows = await pool.query(`
    SELECT id, discord_id, display_name, avatar_url
    FROM accounts ${where}
    ORDER BY LOWER(COALESCE(display_name,'')), discord_id
    LIMIT 20
  `, params);
  res.set("Cache-Control", "no-store");
  res.json({ users: rows.rows });
});

app.get("/api/admin/roles", adminOnly, async (_req, res) => {
  const q = await pool.query(`
    SELECT ar.discord_id, ar.role, ar.granted_by, ar.created_at, a.display_name, a.avatar_url
    FROM admin_roles ar
    LEFT JOIN accounts a ON a.discord_id=ar.discord_id
    WHERE ar.revoked_at IS NULL
    ORDER BY CASE ar.role WHEN 'owner' THEN 1 WHEN 'admin' THEN 2 WHEN 'moderator' THEN 3 ELSE 9 END, ar.created_at ASC
  `);
  res.json(q.rows);
});

app.post("/api/admin/roles", adminOnly, ownerOnly, async (req, res) => {
  const discordId = String(req.body?.discordId || '').trim();
  const role = String(req.body?.role || 'admin').toLowerCase();
  if (!/^\d{15,22}$/.test(discordId)) return res.status(400).json({ error: "Enter a valid Discord user ID." });
  if (!["admin","moderator"].includes(role)) return res.status(400).json({ error: "Role must be Admin or Moderator." });
  const existing = await pool.query("SELECT id, role FROM admin_roles WHERE discord_id=$1 AND revoked_at IS NULL", [discordId]);
  if (existing.rows.length) return res.status(409).json({ error: "That Discord account already has an active role." });
  const grantedBy = req.admin?.discordId || 'admin_key';
  const q = await pool.query("INSERT INTO admin_roles (discord_id, role, granted_by) VALUES ($1,$2,$3) RETURNING *", [discordId, role, grantedBy]);
  await pool.query("INSERT INTO audit_logs (actor, action, details) VALUES ($1,'ADMIN_ROLE_GRANTED',$2)", [req.admin?.accountId || 'admin', JSON.stringify({ discordId, role, grantedBy })]);
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

app.get("/api/admin/me", adminOnly, async (req, res) => {
  let displayName = null;
  if (req.admin?.accountId) {
    const q = await pool.query("SELECT display_name FROM accounts WHERE id=$1", [req.admin.accountId]);
    displayName = q.rows[0]?.display_name || null;
  }
  res.json({ ok: true, role: req.admin?.role || "admin", source: req.admin?.source || "admin_key", discordId: req.admin?.discordId || null, displayName });
});

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



app.get("/api/admin/seasons", adminOrOwner, async (_req, res) => {
  try {
    const q = await pool.query(`
      SELECT s.*,
        COALESCE((SELECT COUNT(*) FROM season_players sp WHERE sp.season_id=s.id AND sp.status='ACTIVE'),0)::int AS player_count,
        COALESCE((SELECT COUNT(*) FROM season_matches sm WHERE sm.season_id=s.id),0)::int AS match_count,
        COALESCE((SELECT COUNT(*) FROM season_markets sk WHERE sk.season_id=s.id),0)::int AS market_count
      FROM seasons s
      ORDER BY s.season_number DESC
    `);
    res.set("Cache-Control", "no-store");
    res.json(q.rows);
  } catch (e) {
    console.error("GET /api/admin/seasons", e);
    res.status(500).json({ error: "Unable to load Test Seasons." });
  }
});

app.post("/api/admin/seasons", adminOrOwner, async (req, res) => {
  const name = String(req.body?.name || "").trim().slice(0, 120);
  const description = String(req.body?.description || "").trim().slice(0, 1000);
  const startingBalance = Number(req.body?.startingBalance);
  if (!name) return res.status(400).json({ error: "Season name is required." });
  if (!Number.isFinite(startingBalance) || startingBalance < 0 || startingBalance > 1_000_000_000) {
    return res.status(400).json({ error: "Starting balance must be a valid non-negative amount." });
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT pg_advisory_xact_lock(817263514)");
    const n = await client.query("SELECT COALESCE(MAX(season_number),0)+1 AS next_number FROM seasons");
    const seasonNumber = Number(n.rows[0].next_number);
    const id = crypto.randomUUID();
    const actor = req.admin?.discordId || req.admin?.accountId || "admin";
    const q = await client.query(`
      INSERT INTO seasons (id, season_number, name, description, status, starting_balance, created_by)
      VALUES ($1,$2,$3,$4,'DRAFT',$5,$6)
      RETURNING *
    `, [id, seasonNumber, name, description, startingBalance, actor]);
    await client.query(
      `INSERT INTO audit_logs (actor, action, details, season_id) VALUES ($1,'TEST_SEASON_CREATED',$2,$3)`,
      [actor, JSON.stringify({ seasonId: id, seasonNumber, name, startingBalance }), id]
    );
    await client.query("COMMIT");
    res.status(201).json({ ok: true, season: q.rows[0] });
  } catch (e) {
    await client.query("ROLLBACK");
    console.error("POST /api/admin/seasons", e);
    res.status(400).json({ error: e.message || "Unable to create Test Season." });
  } finally {
    client.release();
  }
});

app.post("/api/admin/seasons/:id/status", adminOrOwner, async (req, res) => {
  const id = String(req.params.id || "");
  const next = String(req.body?.status || "").toUpperCase();
  const allowed = new Set(["REGISTRATION","LIVE","PAUSED","COMPLETED","ARCHIVED"]);
  if (!allowed.has(next)) return res.status(400).json({ error: "Invalid Test Season status." });

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const q = await client.query("SELECT * FROM seasons WHERE id=$1 FOR UPDATE", [id]);
    if (!q.rows.length) { await client.query("ROLLBACK"); return res.status(404).json({ error: "Test Season not found." }); }
    const current = q.rows[0];
    const transitions = {
      DRAFT: ["REGISTRATION"],
      REGISTRATION: ["LIVE"],
      LIVE: ["PAUSED","COMPLETED"],
      PAUSED: ["LIVE","COMPLETED"],
      COMPLETED: ["ARCHIVED"],
      ARCHIVED: []
    };
    if (!transitions[current.status]?.includes(next)) {
      await client.query("ROLLBACK");
      return res.status(409).json({ error: `Cannot change season from ${current.status} to ${next}.` });
    }
    const actor = req.admin?.discordId || req.admin?.accountId || "admin";
    const sets = ["status=$1"];
    const params = [next];
    if (next === "REGISTRATION") sets.push(`registration_open_at=COALESCE(registration_open_at,NOW())`);
    if (next === "LIVE") sets.push(`started_at=COALESCE(started_at,NOW())`);
    if (next === "COMPLETED") sets.push(`ended_at=COALESCE(ended_at,NOW())`);
    if (next === "ARCHIVED") sets.push(`archived_at=COALESCE(archived_at,NOW())`);
    params.push(id);
    const updated = await client.query(`UPDATE seasons SET ${sets.join(", ")} WHERE id=$${params.length} RETURNING *`, params);
    await client.query(
      `INSERT INTO audit_logs (actor, action, details, season_id) VALUES ($1,'TEST_SEASON_STATUS_CHANGED',$2,$3)`,
      [actor, JSON.stringify({ previousStatus: current.status, newStatus: next }), id]
    );
    await client.query("COMMIT");
    res.json({ ok: true, season: updated.rows[0] });
  } catch (e) {
    await client.query("ROLLBACK");
    console.error("POST /api/admin/seasons/:id/status", e);
    res.status(400).json({ error: e.message || "Unable to update Test Season." });
  } finally {
    client.release();
  }
});

app.get("/api/admin/season-accounts/search", adminOrOwner, async (req, res) => {
  const qText = String(req.query?.q || "").trim();
  const seasonId = String(req.query?.seasonId || "").trim();
  if (!seasonId) return res.status(400).json({ error: "Season ID is required." });
  if (!qText || qText.length < 2) return res.json([]);
  try {
    const like = `%${qText}%`;
    const q = await pool.query(`
      SELECT a.id, a.discord_id, a.display_name, a.avatar_url,
             EXISTS(
               SELECT 1 FROM season_players sp
               WHERE sp.season_id=$2 AND sp.account_id=a.id AND sp.status='ACTIVE'
             ) AS enrolled,
             EXISTS(
               SELECT 1 FROM season_players sp
               WHERE sp.season_id=$2 AND sp.account_id=a.id AND sp.status='REMOVED'
             ) AS previously_enrolled
      FROM accounts a
      WHERE (a.display_name ILIKE $1 OR a.discord_id ILIKE $1)
      ORDER BY LOWER(COALESCE(a.display_name,'')), a.discord_id
      LIMIT 20
    `, [like, seasonId]);
    res.set("Cache-Control", "no-store");
    res.json(q.rows);
  } catch (e) {
    console.error("GET /api/admin/season-accounts/search", e);
    res.status(500).json({ error: "Unable to search Ossper accounts." });
  }
});

app.get("/api/admin/seasons/:id/players", adminOrOwner, async (req, res) => {
  const seasonId = String(req.params.id || "");
  try {
    const q = await pool.query(`
      SELECT sp.*, a.display_name, a.discord_id, a.avatar_url,
             COALESCE(ss.predictions,0)::int AS predictions,
             COALESCE(ss.correct_predictions,0)::int AS correct_predictions,
             COALESCE(ss.incorrect_predictions,0)::int AS incorrect_predictions,
             COALESCE(ss.points_won,0) AS points_won,
             COALESCE(ss.points_lost,0) AS points_lost,
             COALESCE(ss.roi,0) AS roi,
             COALESCE(ss.accuracy,0) AS accuracy,
             ss.current_rank
      FROM season_players sp
      JOIN accounts a ON a.id=sp.account_id
      LEFT JOIN season_stats ss ON ss.season_id=sp.season_id AND ss.account_id=sp.account_id
      WHERE sp.season_id=$1
      ORDER BY CASE sp.status WHEN 'ACTIVE' THEN 0 WHEN 'SUSPENDED' THEN 1 ELSE 2 END,
               LOWER(COALESCE(a.display_name,'')), a.discord_id
    `, [seasonId]);
    res.set("Cache-Control", "no-store");
    res.json(q.rows);
  } catch (e) {
    console.error("GET /api/admin/seasons/:id/players", e);
    res.status(500).json({ error: "Unable to load season players." });
  }
});

app.post("/api/admin/seasons/:id/players", adminOrOwner, async (req, res) => {
  const seasonId = String(req.params.id || "");
  const accountId = String(req.body?.accountId || "");
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(accountId)) {
    return res.status(400).json({ error: "A valid Ossper account is required." });
  }
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const sq = await client.query("SELECT * FROM seasons WHERE id=$1 FOR UPDATE", [seasonId]);
    if (!sq.rows.length) { await client.query("ROLLBACK"); return res.status(404).json({ error: "Test Season not found." }); }
    const season = sq.rows[0];
    if (!["DRAFT","REGISTRATION"].includes(season.status)) {
      await client.query("ROLLBACK");
      return res.status(409).json({ error: "Players can only be enrolled while the season is in DRAFT or REGISTRATION." });
    }
    const aq = await client.query("SELECT id,display_name,discord_id FROM accounts WHERE id=$1", [accountId]);
    if (!aq.rows.length) { await client.query("ROLLBACK"); return res.status(404).json({ error: "Ossper account not found." }); }
    const existing = await client.query("SELECT * FROM season_players WHERE season_id=$1 AND account_id=$2 FOR UPDATE", [seasonId,accountId]);
    const actor = req.admin?.discordId || req.admin?.accountId || "admin";
    const starting = Number(season.starting_balance);
    let player;
    if (existing.rows.length) {
      const old = existing.rows[0];
      if (old.status === "ACTIVE") { await client.query("ROLLBACK"); return res.status(409).json({ error: "That player is already enrolled in this season." }); }
      if (old.status !== "REMOVED") { await client.query("ROLLBACK"); return res.status(409).json({ error: "That player cannot be re-enrolled from its current status." }); }
      const upd = await client.query(`
        UPDATE season_players
        SET status='ACTIVE', starting_balance=$1, current_balance=$1, locked_balance=0,
            realized_pnl=0, total_wagered=0, total_winnings=0, total_losses=0,
            joined_at=NOW(), final_rank=NULL, final_points=NULL
        WHERE id=$2 RETURNING *
      `, [starting, old.id]);
      player = upd.rows[0];
      await client.query(`
        INSERT INTO season_wallet_entries
          (season_id,account_id,type,amount,balance_after,reference_type,reference_id)
        VALUES ($1,$2,'SEASON_REENROLLED',$3,$3,'SEASON_PLAYER',$4)
      `, [seasonId,accountId,starting,String(player.id)]);
      await client.query("UPDATE season_stats SET predictions=0,correct_predictions=0,incorrect_predictions=0,points_won=0,points_lost=0,roi=0,accuracy=0,current_rank=NULL WHERE season_id=$1 AND account_id=$2",[seasonId,accountId]);
    } else {
      const id=crypto.randomUUID();
      const ins=await client.query(`
        INSERT INTO season_players
          (id,season_id,account_id,starting_balance,current_balance,locked_balance,status)
        VALUES ($1,$2,$3,$4,$4,0,'ACTIVE') RETURNING *
      `,[id,seasonId,accountId,starting]);
      player=ins.rows[0];
      await client.query(`
        INSERT INTO season_wallet_entries
          (season_id,account_id,type,amount,balance_after,reference_type,reference_id)
        VALUES ($1,$2,'SEASON_INITIAL_BALANCE',$3,$3,'SEASON_PLAYER',$4)
      `,[seasonId,accountId,starting,id]);
      await client.query(`
        INSERT INTO season_stats (id,season_id,account_id)
        VALUES ($1,$2,$3) ON CONFLICT (season_id,account_id) DO NOTHING
      `,[crypto.randomUUID(),seasonId,accountId]);
    }
    await client.query(`INSERT INTO audit_logs(actor,action,details,season_id) VALUES($1,'TEST_SEASON_PLAYER_ENROLLED',$2,$3)`,[actor,JSON.stringify({accountId,displayName:aq.rows[0].display_name||null,discordId:aq.rows[0].discord_id||null,startingBalance:starting,reEnrolled:Boolean(existing.rows.length)}),seasonId]);
    await client.query("COMMIT");
    res.status(201).json({ok:true,player});
  } catch(e) {
    await client.query("ROLLBACK");
    console.error("POST /api/admin/seasons/:id/players",e);
    res.status(400).json({error:e.message||"Unable to enroll player."});
  } finally { client.release(); }
});

app.post("/api/admin/seasons/:seasonId/roster-import", adminOrOwner, async (req,res)=>{
  const seasonId=String(req.params.seasonId||'');
  const raw=String(req.body?.roster||'');
  const lines=raw.split(/\r?\n/).map(v=>v.trim()).filter(Boolean);
  if(!lines.length) return res.status(400).json({error:'Paste at least 2 player names.'});
  if(lines.length>32) return res.status(400).json({error:'Roster import is capped at 32 players for this test engine.'});
  const parsed=[];
  const seen=new Set();
  for(const line of lines){
    const parts=line.split(/\s*\|\s*|\s*,\s*/,2).map(v=>v.trim()).filter(Boolean);
    const displayName=String(parts[0]||'').slice(0,100);
    const suppliedDiscordId=parts[1] ? String(parts[1]).slice(0,100) : '';
    if(displayName.length<1) continue;
    const key=(suppliedDiscordId||displayName).toLowerCase();
    if(seen.has(key)) return res.status(400).json({error:`Duplicate roster entry: ${displayName}`});
    seen.add(key);
    parsed.push({displayName,suppliedDiscordId});
  }
  if(parsed.length<2) return res.status(400).json({error:'At least 2 players are required.'});
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    const sq=await client.query('SELECT * FROM seasons WHERE id=$1 FOR UPDATE',[seasonId]);
    if(!sq.rows.length) throw new Error('Test Season not found.');
    const season=sq.rows[0];
    if(!['DRAFT','REGISTRATION'].includes(season.status)) throw new Error('Roster import is only available before the test season starts.');
    const existingMatches=await client.query('SELECT COUNT(*)::int AS count FROM season_matches WHERE season_id=$1',[seasonId]);
    if(Number(existingMatches.rows[0].count)>0) throw new Error('This season already has matches. Import the roster before generating the bracket.');
    const starting=Number(season.starting_balance);
    const imported=[];
    for(const entry of parsed){
      const rosterKey='ossper-test-roster:'+crypto.createHash('sha256').update((entry.suppliedDiscordId||entry.displayName).toLowerCase()).digest('hex').slice(0,40);
      let aq=await client.query('SELECT id,display_name,discord_id FROM accounts WHERE test_roster_key=$1 FOR UPDATE',[rosterKey]);
      let account;
      if(aq.rows.length){
        account=aq.rows[0];
        await client.query(`UPDATE accounts SET display_name=$1, discord_id=$2, auth_provider='test' WHERE id=$3`,[entry.displayName,entry.suppliedDiscordId||account.discord_id||('test:'+rosterKey.slice(-12)),account.id]);
      }else{
        const id=crypto.randomUUID();
        const discordId=entry.suppliedDiscordId||('test:'+rosterKey.slice(-12));
        const ins=await client.query(`INSERT INTO accounts(id,balance,discord_id,display_name,auth_provider,test_roster_key) VALUES($1,500,$2,$3,'test',$4) RETURNING id,display_name,discord_id`,[id,discordId,entry.displayName,rosterKey]);
        account=ins.rows[0];
      }
      const existing=await client.query('SELECT * FROM season_players WHERE season_id=$1 AND account_id=$2 FOR UPDATE',[seasonId,account.id]);
      let player;
      if(existing.rows.length && existing.rows[0].status==='ACTIVE'){
        player=existing.rows[0];
      }else if(existing.rows.length && existing.rows[0].status==='REMOVED'){
        const upd=await client.query(`UPDATE season_players SET status='ACTIVE',starting_balance=$1,current_balance=$1,locked_balance=0,realized_pnl=0,total_wagered=0,total_winnings=0,total_losses=0,competitive_points=0,matches_played=0,wins=0,losses=0,tournaments_played=0,tournament_wins=0,joined_at=NOW(),final_rank=NULL,final_points=NULL WHERE id=$2 RETURNING *`,[starting,existing.rows[0].id]);
        player=upd.rows[0];
        await client.query(`INSERT INTO season_wallet_entries(season_id,account_id,type,amount,balance_after,reference_type,reference_id) VALUES($1,$2,'SEASON_REENROLLED',$3,$3,'SEASON_PLAYER',$4)`,[seasonId,account.id,starting,String(player.id)]);
      }else{
        const id=crypto.randomUUID();
        const ins=await client.query(`INSERT INTO season_players(id,season_id,account_id,starting_balance,current_balance,locked_balance,status) VALUES($1,$2,$3,$4,$4,0,'ACTIVE') RETURNING *`,[id,seasonId,account.id,starting]);
        player=ins.rows[0];
        await client.query(`INSERT INTO season_wallet_entries(season_id,account_id,type,amount,balance_after,reference_type,reference_id) VALUES($1,$2,'SEASON_INITIAL_BALANCE',$3,$3,'SEASON_PLAYER',$4)`,[seasonId,account.id,starting,id]);
        await client.query(`INSERT INTO season_stats(id,season_id,account_id) VALUES($1,$2,$3) ON CONFLICT (season_id,account_id) DO NOTHING`,[crypto.randomUUID(),seasonId,account.id]);
      }
      imported.push({accountId:account.id,playerId:player.id,displayName:entry.displayName,discordId:account.discord_id,testAccount:true});
    }
    const actor=req.admin?.discordId||req.admin?.accountId||'admin';
    await client.query(`INSERT INTO audit_logs(actor,action,details,season_id) VALUES($1,'TEST_SEASON_ROSTER_IMPORTED',$2,$3)`,[actor,JSON.stringify({count:imported.length,players:imported.map(x=>({accountId:x.accountId,displayName:x.displayName,discordId:x.discordId}))}),seasonId]);
    await client.query('COMMIT');
    res.status(201).json({ok:true,count:imported.length,players:imported});
  }catch(e){await client.query('ROLLBACK');console.error('POST season roster import',e);res.status(400).json({error:e.message||'Unable to import roster.'});}
  finally{client.release();}
});

app.post("/api/admin/seasons/:seasonId/players/:playerId/status", adminOrOwner, async (req,res)=>{
  const seasonId=String(req.params.seasonId||"");
  const playerId=String(req.params.playerId||"");
  const next=String(req.body?.status||"").toUpperCase();
  if(!["ACTIVE","SUSPENDED","REMOVED"].includes(next)) return res.status(400).json({error:"Invalid player status."});
  const client=await pool.connect();
  try{
    await client.query("BEGIN");
    const q=await client.query("SELECT sp.*,s.status AS season_status FROM season_players sp JOIN seasons s ON s.id=sp.season_id WHERE sp.id=$1 AND sp.season_id=$2 FOR UPDATE",[playerId,seasonId]);
    if(!q.rows.length){await client.query("ROLLBACK");return res.status(404).json({error:"Season player not found."});}
    const row=q.rows[0];
    if(next==='REMOVED' && !['DRAFT','REGISTRATION'].includes(row.season_status)) {await client.query("ROLLBACK");return res.status(409).json({error:"Players can only be removed before the season starts."});}
    if(next==='SUSPENDED' && !['LIVE','PAUSED'].includes(row.season_status)) {await client.query("ROLLBACK");return res.status(409).json({error:"Players can only be suspended during a live or paused season."});}
    if(next==='ACTIVE' && row.status==='REMOVED' && !['DRAFT','REGISTRATION'].includes(row.season_status)) {await client.query("ROLLBACK");return res.status(409).json({error:"A removed player can only be restored before the season starts."});}
    if(next==='ACTIVE' && row.status==='SUSPENDED' && !['LIVE','PAUSED'].includes(row.season_status)) {await client.query("ROLLBACK");return res.status(409).json({error:"A suspended player can only be restored while the season is live or paused."});}
    const updated=await client.query("UPDATE season_players SET status=$1 WHERE id=$2 RETURNING *",[next,playerId]);
    const actor=req.admin?.discordId||req.admin?.accountId||'admin';
    await client.query(`INSERT INTO audit_logs(actor,action,details,season_id) VALUES($1,'TEST_SEASON_PLAYER_STATUS_CHANGED',$2,$3)`,[actor,JSON.stringify({playerId,accountId:row.account_id,previousStatus:row.status,newStatus:next}),seasonId]);
    await client.query("COMMIT");
    res.json({ok:true,player:updated.rows[0]});
  }catch(e){await client.query("ROLLBACK");console.error("POST /api/admin/seasons/:seasonId/players/:playerId/status",e);res.status(400).json({error:e.message||"Unable to update player status."});}
  finally{client.release();}
});

/* Phase 5 — Competitive tournament engine */
const COMPETITIVE_POINTS = Object.freeze({ PARTICIPATION: 10, WIN: 25 });
const ELO_START = 1200;
const ELO_K = 32;

function eloExpected(playerRating, opponentRating) {
  return 1 / (1 + Math.pow(10, (opponentRating - playerRating) / 400));
}

async function ensurePlayerRating(client, accountId) {
  const q = await client.query(`
    INSERT INTO player_ratings (account_id, rating, peak_rating)
    VALUES ($1,$2,$2)
    ON CONFLICT (account_id) DO UPDATE SET account_id=EXCLUDED.account_id
    RETURNING *
  `, [accountId, ELO_START]);
  return q.rows[0];
}

async function awardCompetitivePoints(client, { seasonId, accountId, matchId, entryType, points, details = {} }) {
  const existing = await client.query(`
    SELECT id FROM season_point_entries
    WHERE season_id=$1 AND account_id=$2 AND match_id=$3 AND entry_type=$4
    LIMIT 1
  `, [seasonId, accountId, matchId, entryType]);
  if (existing.rows.length) return { awarded: false };
  const locked = await client.query(`SELECT competitive_points FROM season_players WHERE season_id=$1 AND account_id=$2 FOR UPDATE`, [seasonId, accountId]);
  if (!locked.rows.length) throw new Error('Competitive player record not found.');
  const before = Number(locked.rows[0].competitive_points || 0);
  const after = before + Number(points);
  await client.query(`UPDATE season_players SET competitive_points=$1 WHERE season_id=$2 AND account_id=$3`, [after, seasonId, accountId]);
  await client.query(`
    INSERT INTO season_point_entries (id,season_id,account_id,match_id,entry_type,points,balance_before,balance_after,reference,details)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
  `, [crypto.randomUUID(), seasonId, accountId, matchId, entryType, points, before, after, `MATCH:${matchId}:${entryType}`, JSON.stringify(details)]);
  return { awarded: true, before, after };
}

async function recordCompetitiveMatchResult(client, matchId, winnerSide, actor) {
  const q = await client.query(`SELECT * FROM season_matches WHERE id=$1 FOR UPDATE`, [matchId]);
  if (!q.rows.length) throw new Error('Season match not found.');
  const match = q.rows[0];
  if (match.status !== 'LIVE') throw new Error('Only LIVE matches can be completed.');
  if (!['A','B'].includes(winnerSide)) throw new Error('Winner side must be A or B.');
  const winners = winnerSide === 'A' ? (match.participant_a_ids || []) : (match.participant_b_ids || []);
  const losers = winnerSide === 'A' ? (match.participant_b_ids || []) : (match.participant_a_ids || []);
  if (!winners.length || !losers.length) throw new Error('Both sides need enrolled players before recording a result.');

  const allIds = [...new Set([...winners, ...losers])];
  const ratings = new Map();
  for (const id of allIds) ratings.set(id, await ensurePlayerRating(client, id));
  const avg = ids => ids.reduce((sum,id)=>sum+Number(ratings.get(id)?.rating||ELO_START),0)/ids.length;
  const winnerAvg = avg(winners), loserAvg = avg(losers);
  const winnerExpected = eloExpected(winnerAvg, loserAvg);
  const winnerDelta = Math.max(-ELO_K, Math.min(ELO_K, Math.round(ELO_K * (1 - winnerExpected))));
  const loserDelta = -winnerDelta;

  for (const id of allIds) {
    const isWinner = winners.includes(id);
    const before = Number(ratings.get(id).rating || ELO_START);
    const delta = isWinner ? winnerDelta : loserDelta;
    const after = before + delta;
    await client.query(`
      INSERT INTO player_ratings (account_id,rating,matches_played,wins,losses,peak_rating,updated_at)
      VALUES ($1,$2,1,$3,$4,$2,NOW())
      ON CONFLICT (account_id) DO UPDATE SET
        rating=$2,
        matches_played=player_ratings.matches_played+1,
        wins=player_ratings.wins+$3,
        losses=player_ratings.losses+$4,
        peak_rating=GREATEST(player_ratings.peak_rating,$2),
        updated_at=NOW()
      RETURNING *
    `, [id, after, isWinner ? 1 : 0, isWinner ? 0 : 1]);
    await client.query(`INSERT INTO rating_history (id,account_id,season_id,match_id,rating_before,rating_after,delta,opponent_rating,result) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, [crypto.randomUUID(), id, match.season_id, match.id, before, after, delta, Math.round(isWinner ? loserAvg : winnerAvg), isWinner ? 'WIN' : 'LOSS']);
    await client.query(`UPDATE season_players SET matches_played=matches_played+1,wins=wins+$1,losses=losses+$2 WHERE season_id=$3 AND account_id=$4`, [isWinner ? 1 : 0, isWinner ? 0 : 1, match.season_id, id]);
    await awardCompetitivePoints(client,{seasonId:match.season_id,accountId:id,matchId:match.id,entryType:'MATCH_PARTICIPATION',points:COMPETITIVE_POINTS.PARTICIPATION,details:{round:match.round_number,bracketPhase:match.bracket_phase}});
    if (isWinner) await awardCompetitivePoints(client,{seasonId:match.season_id,accountId:id,matchId:match.id,entryType:'MATCH_WIN',points:COMPETITIVE_POINTS.WIN,details:{round:match.round_number,bracketPhase:match.bracket_phase}});
  }

  await client.query(`UPDATE season_matches SET status='COMPLETE',winner=$1,winner_side=$2,resolved_by=$3,completed_at=COALESCE(completed_at,NOW()),result_recorded_at=NOW() WHERE id=$4`, [winnerSide === 'A' ? match.participant_a : match.participant_b, winnerSide, actor, match.id]);
  await client.query(`INSERT INTO season_results (id,season_id,match_id,outcome,resolved_by) VALUES ($1,$2,$3,$4,$5)`, [crypto.randomUUID(), match.season_id, match.id, winnerSide, actor]);
  await client.query(`INSERT INTO audit_logs(actor,action,details,season_id) VALUES($1,'COMPETITIVE_MATCH_RESULT_RECORDED',$2,$3)`, [actor, JSON.stringify({matchId:match.id,winnerSide,winnerIds:winners,loserIds:losers,eloDelta:winnerDelta,points:COMPETITIVE_POINTS,bracketPhase:match.bracket_phase}), match.season_id]);

  const winnerTarget = match.next_match_id && match.next_match_side ? { id: match.next_match_id, side: match.next_match_side, ids: winners, label: winnerSide === 'A' ? match.participant_a : match.participant_b, result: 'WINNER' } : null;
  const loserTarget = match.loser_next_match_id && match.loser_next_side ? { id: match.loser_next_match_id, side: match.loser_next_side, ids: losers, label: winnerSide === 'A' ? match.participant_b : match.participant_a, result: 'LOSER' } : null;

  async function feed(target) {
    if (!target) return;
    const col = target.side === 'A' ? 'participant_a_ids' : 'participant_b_ids';
    const labelCol = target.side === 'A' ? 'participant_a' : 'participant_b';
    await client.query(`UPDATE season_matches SET ${col}=$1::uuid[], ${labelCol}=$2 WHERE id=$3`, [target.ids, target.label || 'TBD', target.id]);
  }
  await feed(winnerTarget);
  await feed(loserTarget);

  // Grand-final reset: the winners-bracket champion gets one loss. If the losers-bracket
  // champion wins GF1, schedule the deciding rematch. Otherwise the tournament is over.
  if (match.bracket_phase === 'GRAND_FINAL' && match.round_number === 1) {
    const gf2 = await client.query(`SELECT * FROM season_matches WHERE bracket_id=$1 AND bracket_phase='GRAND_FINAL' AND round_number=2 LIMIT 1 FOR UPDATE`, [match.bracket_id]);
    if (gf2.rows.length) {
      const wbSource = await client.query(`SELECT participant_a_ids,participant_b_ids,winner_side FROM season_matches WHERE id=$1`, [match.source_a_match_id]);
      const wbChampionIds = wbSource.rows.length ? (wbSource.rows[0].winner_side==='A'?wbSource.rows[0].participant_a_ids:wbSource.rows[0].participant_b_ids) : [];
      const winningIds = winners;
      const wbChampionWon = wbChampionIds.some(id => winningIds.includes(id));
      if (wbChampionWon) {
        await client.query(`UPDATE season_matches SET status='CANCELLED',completed_at=NOW(),description='Grand Final reset not needed — Winners Bracket champion won Grand Final #1' WHERE id=$1`, [gf2.rows[0].id]);
      } else {
        const aLabel = match.participant_a;
        const bLabel = match.participant_b;
        await client.query(`UPDATE season_matches SET participant_a_ids=$1::uuid[],participant_b_ids=$2::uuid[],participant_a=$3,participant_b=$4,status='SCHEDULED',resolved_by=NULL,completed_at=NULL,result_recorded_at=NULL,description='Deciding Grand Final reset — the Losers Bracket champion won Grand Final #1' WHERE id=$5`, [winners,losers,aLabel,bLabel,gf2.rows[0].id]);
      }
    }
  }

  await settleAutomaticBracketProgression(client, match.bracket_id);
  return {matchId:match.id,winnerSide,winnerIds:winners,loserIds:losers,eloDelta:winnerDelta};
}

app.get('/api/admin/seasons/:seasonId/leaderboard', adminOrModerator, async (req,res)=>{
  const seasonId=String(req.params.seasonId||'');
  try{
    const q=await pool.query(`
      SELECT sp.account_id,COALESCE(a.display_name,'Unnamed') AS display_name,a.discord_id,
             sp.competitive_points,sp.matches_played,sp.wins,sp.losses,sp.tournaments_played,sp.tournament_wins,
             COALESCE(pr.rating,$2)::int AS rating,
             COALESCE(pr.peak_rating,$2)::int AS peak_rating
      FROM season_players sp JOIN accounts a ON a.id=sp.account_id
      LEFT JOIN player_ratings pr ON pr.account_id=sp.account_id
      WHERE sp.season_id=$1 AND sp.status IN ('ACTIVE','SUSPENDED')
      ORDER BY sp.competitive_points DESC, COALESCE(pr.rating,$2) DESC, sp.wins DESC, LOWER(COALESCE(a.display_name,'')) ASC
    `,[seasonId,ELO_START]);
    res.set('Cache-Control','no-store');res.json(q.rows);
  }catch(e){res.status(500).json({error:'Unable to load competitive leaderboard.'});}
});

app.get('/api/leaderboard', async (_req,res)=>{
  try{
    const q=await pool.query(`SELECT pr.account_id,COALESCE(a.display_name,'Unnamed') AS display_name,a.discord_id,pr.rating,pr.peak_rating,pr.matches_played,pr.wins,pr.losses FROM player_ratings pr JOIN accounts a ON a.id=pr.account_id ORDER BY pr.rating DESC,pr.wins DESC,LOWER(COALESCE(a.display_name,'')) ASC LIMIT 100`);
    res.set('Cache-Control','no-store');res.json(q.rows);
  }catch(e){res.status(500).json({error:'Unable to load ELO leaderboard.'});}
});

/* Phase 3 — Test Season match integration */
app.get("/api/admin/seasons/:seasonId/matches", adminOrModerator, async (req,res)=>{
  const seasonId=String(req.params.seasonId||"");
  try{
    const q=await pool.query(`
      SELECT sm.*, s.name AS season_name, s.status AS season_status,
        COALESCE((SELECT COUNT(*) FROM season_markets sx WHERE sx.match_id=sm.id),0)::int AS market_count,
        COALESCE((SELECT json_agg(json_build_object('id',a.id,'displayName',COALESCE(a.display_name,'Unnamed'),'discordId',a.discord_id) ORDER BY COALESCE(a.display_name,''))
                  FROM accounts a WHERE a.id=ANY(sm.participant_a_ids)), '[]'::json) AS participant_a,
        COALESCE((SELECT json_agg(json_build_object('id',a.id,'displayName',COALESCE(a.display_name,'Unnamed'),'discordId',a.discord_id) ORDER BY COALESCE(a.display_name,''))
                  FROM accounts a WHERE a.id=ANY(sm.participant_b_ids)), '[]'::json) AS participant_b
      FROM season_matches sm JOIN seasons s ON s.id=sm.season_id
      WHERE sm.season_id=$1 ORDER BY sm.match_number ASC`,[seasonId]);
    res.set('Cache-Control','no-store'); res.json(q.rows);
  }catch(e){console.error('GET season matches',e);res.status(500).json({error:'Unable to load season matches.'});}
});

app.post("/api/admin/seasons/:seasonId/matches", adminOrModerator, async (req,res)=>{
  const seasonId=String(req.params.seasonId||"");
  const format=String(req.body?.format||'1v1').toLowerCase();
  const aIds=Array.isArray(req.body?.participantAIds)?req.body.participantAIds.map(String):[];
  const bIds=Array.isArray(req.body?.participantBIds)?req.body.participantBIds.map(String):[];
  const description=String(req.body?.description||'').trim().slice(0,1000);
  const aLabel=String(req.body?.sideA||'').trim().slice(0,160);
  const bLabel=String(req.body?.sideB||'').trim().slice(0,160);
  const scheduledRaw=req.body?.scheduledAt;
  let scheduledAt=null;
  if(scheduledRaw!==null && scheduledRaw!==undefined && String(scheduledRaw).trim()!==""){
    const parsedScheduled=new Date(String(scheduledRaw));
    if(Number.isNaN(parsedScheduled.getTime())) return res.status(400).json({error:'Scheduled time is invalid. Please choose a valid local date and time.'});
    scheduledAt=parsedScheduled.toISOString();
  }
  if(!['1v1','2v2'].includes(format)) return res.status(400).json({error:'Format must be 1v1 or 2v2.'});
  const expected=format==='1v1'?1:2;
  if(aIds.length!==expected || bIds.length!==expected) return res.status(400).json({error:`${format} requires ${expected} participant${expected===1?'':'s'} on each side.`});
  if(new Set([...aIds,...bIds]).size !== aIds.length+bIds.length) return res.status(400).json({error:'A player cannot appear on both sides of the same match.'});
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    const sq=await client.query('SELECT * FROM seasons WHERE id=$1 FOR UPDATE',[seasonId]);
    if(!sq.rows.length) throw new Error('Season not found.');
    const season=sq.rows[0];
    if(!['DRAFT','REGISTRATION','LIVE'].includes(season.status)) throw new Error('Matches can only be created before or during a live season.');
    const ids=[...aIds,...bIds];
    const pq=await client.query(`SELECT account_id,COALESCE(a.display_name,'Unnamed') AS display_name FROM season_players sp JOIN accounts a ON a.id=sp.account_id WHERE sp.season_id=$1 AND sp.status='ACTIVE' AND sp.account_id=ANY($2::uuid[])`,[seasonId,ids]);
    if(pq.rows.length!==ids.length) throw new Error('Every participant must be an active player enrolled in this season.');
    await client.query(`SELECT pg_advisory_xact_lock(hashtext($1))`,[`season-match-${seasonId}`]);
    const nq=await client.query('SELECT COALESCE(MAX(match_number),0)+1 AS next_number FROM season_matches WHERE season_id=$1',[seasonId]);
    const matchNumber=Number(nq.rows[0].next_number);
    const map=new Map(pq.rows.map(r=>[r.account_id,r.display_name]));
    const defaultA=aIds.map(id=>map.get(id)||'Unnamed').join(' + ');
    const defaultB=bIds.map(id=>map.get(id)||'Unnamed').join(' + ');
    const sideA=aLabel||defaultA, sideB=bLabel||defaultB;
    const title=`Match #${String(matchNumber).padStart(3,'0')} · ${sideA} vs ${sideB}`;
    const id=crypto.randomUUID();
    const ins=await client.query(`INSERT INTO season_matches (id,season_id,match_number,title,participant_a,participant_b,status,started_at,format,participant_a_ids,participant_b_ids,description) VALUES ($1,$2,$3,$4,$5,$6,'SCHEDULED',$7,$8,$9::uuid[],$10::uuid[],$11) RETURNING *`,[id,seasonId,matchNumber,title,sideA,sideB,scheduledAt||null,format,aIds,bIds,description]);
    const actor=req.admin?.accountId||req.admin?.discordId||'admin';
    await client.query(`INSERT INTO audit_logs(actor,action,details,season_id) VALUES($1,'TEST_SEASON_MATCH_CREATED',$2,$3)`,[actor,JSON.stringify({matchId:id,matchNumber,format,participantAIds:aIds,participantBIds:bIds,sideA,sideB,scheduledAt}),seasonId]);
    await client.query('COMMIT');
    res.status(201).json({ok:true,match:ins.rows[0]});
  }catch(e){await client.query('ROLLBACK');console.error('POST season match',e);res.status(400).json({error:e.message||'Unable to create season match.'});}
  finally{client.release();}
});

app.post("/api/admin/seasons/:seasonId/restart", adminOrModerator, async (req,res)=>{
  const seasonId=String(req.params.seasonId||'');
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock(hashtext($1))',[`season-restart-${seasonId}`]);
    const sq=await client.query('SELECT * FROM seasons WHERE id=$1 FOR UPDATE',[seasonId]);
    if(!sq.rows.length) throw new Error('Test Season not found.');
    const season=sq.rows[0];
    if(!['REGISTRATION','LIVE','PAUSED'].includes(season.status)) throw new Error('Only an active Test Season can be restarted.');
    const marketLinks=await client.query('SELECT COUNT(*)::int AS count FROM season_markets WHERE season_id=$1',[seasonId]);
    if(Number(marketLinks.rows[0].count)>0) throw new Error('This tournament already has linked prediction markets. Finish/void those markets before restarting; the restart is intentionally non-destructive to market history.');

    const run=Number(season.tournament_run||1);
    const nextRun=run+1;
    const actor=req.admin?.accountId||req.admin?.discordId||'admin';

    // Restore the ELO state captured when the current tournament run began.
    const snap=await client.query(`SELECT * FROM season_competitive_snapshots WHERE season_id=$1 AND run_number=$2`,[seasonId,run]);
    for(const row of snap.rows){
      await client.query(`INSERT INTO player_ratings(account_id,rating,matches_played,wins,losses,peak_rating,updated_at) VALUES($1,$2,$3,$4,$5,$6,NOW()) ON CONFLICT(account_id) DO UPDATE SET rating=EXCLUDED.rating,matches_played=EXCLUDED.matches_played,wins=EXCLUDED.wins,losses=EXCLUDED.losses,peak_rating=EXCLUDED.peak_rating,updated_at=NOW()`,[row.account_id,row.rating,row.matches_played,row.wins,row.losses,row.peak_rating]);
    }

    // Tournament artifacts are reset; the enrolled roster and season identity remain.
    await client.query('DELETE FROM season_results WHERE season_id=$1',[seasonId]);
    await client.query('DELETE FROM season_point_entries WHERE season_id=$1',[seasonId]);
    await client.query('DELETE FROM season_matches WHERE season_id=$1',[seasonId]);
    await client.query(`UPDATE season_players SET competitive_points=0,matches_played=0,wins=0,losses=0,tournaments_played=0,tournament_wins=0,final_rank=NULL,final_points=NULL,status=CASE WHEN status='SUSPENDED' THEN 'ACTIVE' ELSE status END WHERE season_id=$1`,[seasonId]);
    await client.query(`UPDATE season_stats SET predictions=0,correct_predictions=0,incorrect_predictions=0,points_won=0,points_lost=0,roi=0,accuracy=0,current_rank=NULL WHERE season_id=$1`,[seasonId]);
    await client.query(`DELETE FROM season_competitive_snapshots WHERE season_id=$1 AND run_number=$2`,[seasonId,run]);

    await client.query(`UPDATE seasons SET tournament_run=$1,status='REGISTRATION',started_at=NULL,ended_at=NULL,archived_at=NULL,registration_open_at=NOW() WHERE id=$2`,[nextRun,seasonId]);
    await client.query(`INSERT INTO audit_logs(actor,action,details,season_id) VALUES($1,'COMPETITIVE_TOURNAMENT_RESTARTED',$2,$3)`,[actor,JSON.stringify({previousRun:run,newRun:nextRun,restoredRatings:snap.rows.length,rosterPreserved:true}),seasonId]);
    await client.query('COMMIT');
    res.json({ok:true,seasonId,run:nextRun,restoredRatings:snap.rows.length,rosterPreserved:true});
  }catch(e){await client.query('ROLLBACK');res.status(400).json({error:e.message||'Unable to restart tournament.'});}
  finally{client.release();}
});

async function settleAutomaticBracketProgression(client, bracketId) {
  // Resolve winner/loser source slots and automatically advance BYEs. This keeps
  // double-elimination brackets moving even when a non-power-of-two field creates
  // empty loser slots.
  for (let pass = 0; pass < 12; pass++) {
    const q = await client.query(`SELECT * FROM season_matches WHERE bracket_id=$1 ORDER BY match_number ASC`, [bracketId]);
    let changed = false;
    for (const match of q.rows) {
      if (!['SCHEDULED','COMPLETE'].includes(match.status)) continue;
      const sides = [
        {side:'A', sourceId:match.source_a_match_id, sourceResult:match.source_a_result, ids:match.participant_a_ids||[], label:match.participant_a||'TBD'},
        {side:'B', sourceId:match.source_b_match_id, sourceResult:match.source_b_result, ids:match.participant_b_ids||[], label:match.participant_b||'TBD'}
      ];
      let unresolved = false;
      for (const side of sides) {
        if (!side.sourceId) continue;
        const sq = await client.query(`SELECT status,participant_a_ids,participant_b_ids,participant_a,participant_b,winner_side,winner FROM season_matches WHERE id=$1`, [side.sourceId]);
        if (!sq.rows.length || !['COMPLETE','CANCELLED'].includes(sq.rows[0].status)) { unresolved = true; continue; }
        const src = sq.rows[0];
        let ids = [];
        let label = 'TBD';
        if (src.status === 'COMPLETE') {
          if (side.sourceResult === 'WINNER') {
            ids = src.winner_side === 'A' ? (src.participant_a_ids||[]) : (src.participant_b_ids||[]);
            label = src.winner || (src.winner_side === 'A' ? src.participant_a : src.participant_b) || 'TBD';
          } else {
            ids = src.winner_side === 'A' ? (src.participant_b_ids||[]) : (src.participant_a_ids||[]);
            label = src.winner_side === 'A' ? (src.participant_b||'TBD') : (src.participant_a||'TBD');
          }
        }
        const col = side.side === 'A' ? 'participant_a_ids' : 'participant_b_ids';
        const labelCol = side.side === 'A' ? 'participant_a' : 'participant_b';
        const current = side.ids.join(',');
        const next = ids.join(',');
        if (current !== next || String(side.label) !== String(label)) {
          await client.query(`UPDATE season_matches SET ${col}=$1::uuid[],${labelCol}=$2 WHERE id=$3`, [ids,label,match.id]);
          changed = true;
        }
      }
      if (unresolved || !['SCHEDULED'].includes(match.status)) continue;
      const a = (await client.query(`SELECT participant_a_ids,participant_b_ids FROM season_matches WHERE id=$1`, [match.id])).rows[0];
      const aIds = a?.participant_a_ids||[], bIds = a?.participant_b_ids||[];
      if (aIds.length && bIds.length) continue;
      if (!aIds.length && !bIds.length && (match.source_a_match_id || match.source_b_match_id)) continue;
      const winnerSide = aIds.length ? 'A' : (bIds.length ? 'B' : null);
      if (!winnerSide) {
        await client.query(`UPDATE season_matches SET status='CANCELLED',winner=NULL,winner_side=NULL,resolved_by='system:no-contest',completed_at=NOW(),result_recorded_at=NOW() WHERE id=$1`, [match.id]);
      } else {
        const label = winnerSide==='A' ? (await client.query(`SELECT participant_a FROM season_matches WHERE id=$1`,[match.id])).rows[0].participant_a : (await client.query(`SELECT participant_b FROM season_matches WHERE id=$1`,[match.id])).rows[0].participant_b;
        await client.query(`UPDATE season_matches SET status='COMPLETE',winner=$1,winner_side=$2,resolved_by='system:bye',completed_at=NOW(),result_recorded_at=NOW() WHERE id=$3`, [label||'BYE',winnerSide,match.id]);
      }
      changed = true;
    }
    if (!changed) break;
  }
}

app.post("/api/admin/seasons/:seasonId/bracket", adminOrModerator, async (req,res)=>{
  const seasonId=String(req.params.seasonId||'');
  const format=String(req.body?.format||'1v1').toLowerCase();
  if(format!=='1v1') return res.status(400).json({error:'Automatic bracket generation currently supports 1v1. 2v2 remains available through manual match creation.'});
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    const sq=await client.query('SELECT * FROM seasons WHERE id=$1 FOR UPDATE',[seasonId]);
    await client.query('SELECT pg_advisory_xact_lock(hashtext($1))',[`season-bracket-${seasonId}`]);
    if(!sq.rows.length) throw new Error('Season not found.');
    if(!['REGISTRATION','LIVE'].includes(sq.rows[0].status)) throw new Error('The season must be in registration or live status to generate a bracket.');
    const existing=await client.query('SELECT COUNT(*)::int AS count FROM season_matches WHERE season_id=$1',[seasonId]);
    if(Number(existing.rows[0].count)>0) throw new Error('This season already has matches. Generate the bracket before creating matches.');
    const pq=await client.query(`SELECT sp.account_id,COALESCE(a.display_name,'Unnamed') AS display_name FROM season_players sp JOIN accounts a ON a.id=sp.account_id WHERE sp.season_id=$1 AND sp.status='ACTIVE' ORDER BY RANDOM()`,[seasonId]);
    const players=pq.rows;
    if(players.length<2) throw new Error('At least 2 active players are required.');
    if(players.length>32) throw new Error('Automatic brackets are capped at 32 players for this patch.');
    const bracketId=crypto.randomUUID();
    const runNumber=Number(sq.rows[0].tournament_run||1);
    for(const player of players){
      const rating=await ensurePlayerRating(client,player.account_id);
      await client.query(`INSERT INTO season_competitive_snapshots(season_id,run_number,account_id,rating,matches_played,wins,losses,peak_rating) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING`,[seasonId,runNumber,player.account_id,rating.rating,rating.matches_played,rating.wins,rating.losses,rating.peak_rating]);
    }

    // Double-elimination graph. Winners bracket is followed by a standard
    // alternating losers bracket, then a two-game-capable grand final.
    const targetSize=2 ** Math.ceil(Math.log2(players.length));
    const shuffled=[...players];
    for(let i=shuffled.length-1;i>0;i--){const j=Math.floor(Math.random()*(i+1));[shuffled[i],shuffled[j]]=[shuffled[j],shuffled[i]];}
    while(shuffled.length<targetSize) shuffled.push(null);
    const k=Math.log2(targetSize);
    const matches=[];
    const wb=[];
    const lb=[];
    const make=(phase,round,slot)=>({id:crypto.randomUUID(),phase,round,slot,a:[],b:[],sourceA:null,sourceB:null,winnerNext:null,loserNext:null});

    // Winners bracket.
    for(let r=1;r<=k;r++){
      const count=targetSize/(2**r); const arr=[];
      for(let i=0;i<count;i++){
        const m=make('WINNERS',r,i+1);
        if(r===1){ m.a=shuffled[i*2]?[shuffled[i*2]]:[]; m.b=shuffled[i*2+1]?[shuffled[i*2+1]]:[]; }
        else { const prev=wb[r-2]; m.sourceA={match:prev[i*2],result:'WINNER'}; m.sourceB={match:prev[i*2+1],result:'WINNER'}; }
        arr.push(m); matches.push(m);
      }
      wb.push(arr);
    }
    for(let r=1;r<k;r++) for(let i=0;i<wb[r-1].length;i++) wb[r-1][i].winnerNext={match:wb[r][Math.floor(i/2)],side:(i%2===0?'A':'B')};

    // Losers bracket has 2k-2 rounds for a k-round winners bracket.
    const lbRounds=Math.max(0,2*k-2);
    for(let lr=1;lr<=lbRounds;lr++){
      const count=targetSize/(2**(Math.floor((lr-1)/2)+2));
      const arr=[];
      for(let i=0;i<count;i++){const m=make('LOSERS',lr,i+1);arr.push(m);matches.push(m);}
      lb.push(arr);
    }
    if(k>=2){
      // W1 losers feed paired into L1.
      for(let i=0;i<wb[0].length;i++) wb[0][i].loserNext={match:lb[0][Math.floor(i/2)],side:(i%2===0?'A':'B')};
      // W2/W3/... losers enter the even-numbered LB round on side B.
      for(let r=2;r<=k;r++){
        const targetRoundIndex=2*r-3;
        const target=lb[targetRoundIndex];
        for(let i=0;i<wb[r-1].length;i++) wb[r-1][i].loserNext={match:target[i],side:'B'};
      }
      // L2, L4, ... receive a prior LB winner plus the corresponding WB loser.
      // L3, L5, ... pair the winners from the preceding LB round.
      for(let lr=2;lr<=lbRounds;lr++){
        const arr=lb[lr-1];
        if(lr%2===0){
          const wbRound=lr/2+1; // L2 -> W2, L4 -> W3, ...
          const prev=lb[lr-2]; const wbr=wb[wbRound-1];
          for(let i=0;i<arr.length;i++){
            arr[i].sourceA={match:prev[i],result:'WINNER'};
            arr[i].sourceB={match:wbr[i],result:'LOSER'};
          }
        } else {
          const prev=lb[lr-2];
          for(let i=0;i<arr.length;i++){
            arr[i].sourceA={match:prev[i*2],result:'WINNER'};
            arr[i].sourceB={match:prev[i*2+1],result:'WINNER'};
          }
        }
      }
    }
    // LB winner advances through the final LB match; WB final loser enters the
    // last LB round automatically through the same even-round wiring above.
    const lbFinal=lb.length?lb[lb.length-1][0]:null;
    const wbFinal=wb[k-1][0];
    const gf1=make('GRAND_FINAL',1,1);
    gf1.sourceA={match:wbFinal,result:'WINNER'};
    gf1.sourceB=lbFinal?{match:lbFinal,result:'WINNER'}:{match:wbFinal,result:'LOSER'};
    matches.push(gf1);
    const gf2=make('GRAND_FINAL',2,1);
    gf2.sourceA={match:gf1,result:'WINNER'};
    gf2.sourceB={match:gf1,result:'LOSER'};
    matches.push(gf2);

    const idSet=new Set(matches.map(m=>m.id));
    for(const m of matches){
      const aIds=m.a.map(x=>x.account_id), bIds=m.b.map(x=>x.account_id);
      const aLabel=m.a.map(x=>x.display_name).join(' + ')||'TBD';
      const bLabel=m.b.map(x=>x.display_name).join(' + ')||'TBD';
      const title=m.phase==='WINNERS'?`Winners Round ${m.round} · Match ${m.slot}`:m.phase==='LOSERS'?`Losers Round ${m.round} · Match ${m.slot}`:`Grand Final${m.round===2?' Reset':''}`;
      await client.query(`INSERT INTO season_matches (id,season_id,match_number,title,participant_a,participant_b,status,format,participant_a_ids,participant_b_ids,description,round_number,bracket_slot,bracket_id,bracket_phase,source_a_match_id,source_a_result,source_b_match_id,source_b_result) VALUES ($1,$2,(SELECT COALESCE(MAX(match_number),0)+1 FROM season_matches WHERE season_id=$2),$3,$4,$5,'SCHEDULED','1v1',$6::uuid[],$7::uuid[],$8,$9,$10,$11,$12,$13,$14,$15,$16)`,[m.id,seasonId,title,aLabel,bLabel, aIds,bIds,`Double-elimination · ${m.phase==='WINNERS'?'Winners Bracket':m.phase==='LOSERS'?'Losers Bracket':m.round===2?'Grand Final Reset':'Grand Final'} · Run ${runNumber}`,m.round,m.slot,bracketId,m.phase,m.sourceA?.match?.id||null,m.sourceA?.result||null,m.sourceB?.match?.id||null,m.sourceB?.result||null]);
    }
    // Wire winner/loser destinations after all match rows exist.
    for(const m of matches){
      if(m.winnerNext) await client.query(`UPDATE season_matches SET next_match_id=$1,next_match_side=$2 WHERE id=$3`,[m.winnerNext.match.id,m.winnerNext.side,m.id]);
      if(m.loserNext) await client.query(`UPDATE season_matches SET loser_next_match_id=$1,loser_next_side=$2 WHERE id=$3`,[m.loserNext.match.id,m.loserNext.side,m.id]);
    }
    // Grand Final #2 is conditional and starts cancelled until GF1 requires it.
    await client.query(`UPDATE season_matches SET status='CANCELLED',resolved_by='system:conditional',description='Grand Final reset is only played if the Losers Bracket champion wins Grand Final #1.' WHERE id=$1`,[gf2.id]);
    // Let already-known BYEs cascade through both brackets.
    await settleAutomaticBracketProgression(client,bracketId);

    const actor=req.admin?.accountId||req.admin?.discordId||'admin';
    await client.query(`INSERT INTO audit_logs(actor,action,details,season_id) VALUES($1,'COMPETITIVE_BRACKET_GENERATED',$2,$3)`,[actor,JSON.stringify({bracketId,format,playerCount:players.length,rounds:k,losersRounds:lbRounds,grandFinal:true,runNumber}),seasonId]);
    await client.query('COMMIT');
    const qCount=await pool.query(`SELECT COUNT(*)::int AS count FROM season_matches WHERE bracket_id=$1`,[bracketId]);
    res.status(201).json({ok:true,bracketId,playerCount:players.length,rounds:k,losersRounds:lbRounds,matches:qCount.rows[0].count,byes:targetSize-players.length,runNumber,doubleElimination:true});
  }catch(e){await client.query('ROLLBACK');console.error('POST season bracket',e);res.status(400).json({error:e.message||'Unable to generate bracket.'});}
  finally{client.release();}
});

app.post("/api/admin/seasons/:seasonId/matches/:matchId/status", adminOrModerator, async (req,res)=>{
  const seasonId=String(req.params.seasonId||''); const matchId=String(req.params.matchId||''); const next=String(req.body?.status||'').toUpperCase();
  const winner=String(req.body?.winner||'').trim().slice(0,160);
  const winnerSide=String(req.body?.winnerSide||'').toUpperCase();
  if(!['SCHEDULED','LIVE','COMPLETE','CANCELLED'].includes(next)) return res.status(400).json({error:'Invalid match status.'});
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    const q=await client.query('SELECT sm.*,s.status AS season_status FROM season_matches sm JOIN seasons s ON s.id=sm.season_id WHERE sm.id=$1 AND sm.season_id=$2 FOR UPDATE',[matchId,seasonId]);
    if(!q.rows.length) throw new Error('Season match not found.');
    const row=q.rows[0];
    const allowed=(row.status==='SCHEDULED'&&['LIVE','CANCELLED'].includes(next)) || (row.status==='LIVE'&&['COMPLETE','CANCELLED'].includes(next));
    if(!allowed) throw new Error(`Cannot change match from ${row.status} to ${next}.`);
    if(next==='LIVE' && row.season_status!=='LIVE') throw new Error('The season must be LIVE before a match can go LIVE.');
    if(next==='LIVE' && (!(row.participant_a_ids||[]).length || !(row.participant_b_ids||[]).length)) throw new Error('Both sides must be populated before the match can go LIVE.');
    if(next==='COMPLETE') {
      if(!['A','B'].includes(winnerSide)) throw new Error('Choose the winning side: A or B.');
      if(!winner) throw new Error('A winner label is required.');
      const result=await recordCompetitiveMatchResult(client,matchId,winnerSide,req.admin?.accountId||req.admin?.discordId||'admin');
      await client.query('COMMIT');
      return res.json({ok:true,competitive:true,result});
    }
    const sets=['status=$1']; const params=[next];
    if(next==='LIVE'){sets.push('started_at=COALESCE(started_at,NOW())');}
    if(next==='CANCELLED'){sets.push('completed_at=COALESCE(completed_at,NOW())');}
    params.push(matchId);
    const updated=await client.query(`UPDATE season_matches SET ${sets.join(', ')} WHERE id=$${params.length} RETURNING *`,params);
    await client.query(`INSERT INTO audit_logs(actor,action,details,season_id) VALUES($1,'TEST_SEASON_MATCH_STATUS_CHANGED',$2,$3)`,[req.admin?.accountId||req.admin?.discordId||'admin',JSON.stringify({matchId,previousStatus:row.status,newStatus:next,winner:null}),seasonId]);
    await client.query('COMMIT'); res.json({ok:true,match:updated.rows[0]});
  }catch(e){await client.query('ROLLBACK');res.status(400).json({error:e.message||'Unable to update season match.'});}finally{client.release();}
});

app.get('/api/admin/seasons/:seasonId/eliminations', adminOrModerator, async (req,res)=>{
  const seasonId=String(req.params.seasonId||'');
  try{
    const players=await pool.query(`SELECT sp.account_id,COALESCE(a.display_name,'Unnamed') AS display_name FROM season_players sp JOIN accounts a ON a.id=sp.account_id WHERE sp.season_id=$1 AND sp.status IN ('ACTIVE','SUSPENDED')`,[seasonId]);
    const matches=await pool.query(`SELECT id,match_number,title,round_number,bracket_phase,participant_a_ids,participant_b_ids,participant_a,participant_b,winner_side,status,completed_at FROM season_matches WHERE season_id=$1 AND bracket_phase IN ('WINNERS','LOSERS','GRAND_FINAL') ORDER BY match_number ASC`,[seasonId]);
    const losses=new Map(players.rows.map(p=>[p.account_id,{accountId:p.account_id,displayName:p.display_name,losses:0,eliminationMatch:null,eliminationPhase:null}]));
    for(const m of matches.rows){
      if(m.status!=='COMPLETE' || !['A','B'].includes(m.winner_side) || m.resolved_by==='system:bye') continue;
      const ids=m.winner_side==='A'?(m.participant_b_ids||[]):(m.participant_a_ids||[]);
      for(const id of ids){
        const row=losses.get(id); if(!row) continue;
        row.losses++;
        if(row.losses>=2 && !row.eliminationMatch) { row.eliminationMatch={matchId:m.id,matchNumber:m.match_number,title:m.title,phase:m.bracket_phase,round:m.round_number}; row.eliminationPhase=m.bracket_phase; }
      }
    }
    const all=[...losses.values()];
    const eliminated=all.filter(x=>x.losses>=2).sort((a,b)=>(a.eliminationMatch?.matchNumber||0)-(b.eliminationMatch?.matchNumber||0));
    const alive=all.filter(x=>x.losses<2).sort((a,b)=>a.losses-b.losses||a.displayName.localeCompare(b.displayName));
    const gf=matches.rows.filter(m=>m.bracket_phase==='GRAND_FINAL' && m.status==='COMPLETE').sort((a,b)=>Number(a.round_number)-Number(b.round_number));
    let champion=null;
    const finalMatch=gf.length?gf[gf.length-1]:null;
    if(finalMatch && ['A','B'].includes(finalMatch.winner_side)){
      const id=(finalMatch.winner_side==='A'?(finalMatch.participant_a_ids||[]):(finalMatch.participant_b_ids||[]))[0];
      champion=all.find(x=>x.accountId===id)||null;
    }
    res.set('Cache-Control','no-store');res.json({eliminated,alive,champion});
  }catch(e){console.error('GET season eliminations',e);res.status(500).json({error:'Unable to load elimination breakdown.'});}
});

app.get("/api/season/public", async (_req,res)=>{
  try{
    const sq=await pool.query(`
      SELECT s.id,s.season_number,s.name,s.description,s.status,s.starting_balance,
             s.created_at,s.registration_open_at,s.started_at,s.ended_at,
             COALESCE((SELECT COUNT(*) FROM season_players sp WHERE sp.season_id=s.id AND sp.status='ACTIVE'),0)::int AS player_count,
             COALESCE((SELECT COUNT(*) FROM season_matches sm WHERE sm.season_id=s.id),0)::int AS match_count,
             COALESCE((SELECT COUNT(*) FROM season_markets sk WHERE sk.season_id=s.id),0)::int AS market_count
      FROM seasons s
      WHERE s.status IN ('REGISTRATION','LIVE','PAUSED')
      ORDER BY CASE s.status WHEN 'LIVE' THEN 0 WHEN 'PAUSED' THEN 1 ELSE 2 END,
               s.started_at DESC NULLS LAST,s.created_at DESC
      LIMIT 1
    `);
    res.set('Cache-Control','no-store');
    if(!sq.rows.length) return res.json({active:false,season:null,matches:[]});
    const s=sq.rows[0];
    const mq=await pool.query(`
      SELECT sm.id,sm.match_number,sm.title,sm.participant_a,sm.participant_b,sm.status,
             sm.winner,sm.scheduled_at,sm.started_at,sm.completed_at,sm.format,sm.description,
             COALESCE((SELECT COUNT(*) FROM season_markets sx WHERE sx.match_id=sm.id),0)::int AS market_count
      FROM season_matches sm
      WHERE sm.season_id=$1
      ORDER BY sm.match_number ASC
    `,[s.id]);
    res.json({
      active:true,
      season:{
        id:s.id,seasonNumber:s.season_number,name:s.name,description:s.description,status:s.status,
        startingBalance:Number(s.starting_balance),createdAt:s.created_at,registrationOpenAt:s.registration_open_at,
        startedAt:s.started_at,endedAt:s.ended_at,
        playerCount:Number(s.player_count),matchCount:Number(s.match_count),marketCount:Number(s.market_count)
      },
      matches:mq.rows
    });
  }catch(e){
    console.error('GET /api/season/public',e);
    res.status(500).json({error:'Unable to load the active Test Season.'});
  }
});

app.get("/api/season/me", async (req,res)=>{
  const accountId=await requestAccountId(req);
  if(!accountId) return res.json({enrolled:false,season:null,player:null});
  try{
    const q=await pool.query(`
      SELECT s.id AS season_id,s.season_number,s.name,s.description,s.status,s.starting_balance,
             s.created_at,s.registration_open_at,s.started_at,s.ended_at,
             sp.id AS player_id,sp.status AS player_status,sp.starting_balance AS player_starting_balance,
             sp.current_balance,sp.locked_balance,sp.realized_pnl,sp.total_wagered,sp.total_winnings,sp.total_losses,
             COALESCE(ss.predictions,0)::int AS predictions,
             COALESCE(ss.correct_predictions,0)::int AS correct_predictions,
             COALESCE(ss.incorrect_predictions,0)::int AS incorrect_predictions,
             COALESCE(ss.roi,0) AS roi,COALESCE(ss.accuracy,0) AS accuracy,ss.current_rank
      FROM season_players sp
      JOIN seasons s ON s.id=sp.season_id
      LEFT JOIN season_stats ss ON ss.season_id=sp.season_id AND ss.account_id=sp.account_id
      WHERE sp.account_id=$1 AND s.status IN ('REGISTRATION','LIVE','PAUSED') AND sp.status IN ('ACTIVE','SUSPENDED')
      ORDER BY CASE s.status WHEN 'LIVE' THEN 0 WHEN 'PAUSED' THEN 1 ELSE 2 END,s.started_at DESC NULLS LAST,s.created_at DESC
      LIMIT 1
    `,[accountId]);
    res.set("Cache-Control","no-store");
    if(!q.rows.length) return res.json({enrolled:false,season:null,player:null});
    const r=q.rows[0];
    const totalPoints=Number(r.current_balance||0);
    const locked=Number(r.locked_balance||0);
    res.json({
      enrolled:true,
      season:{id:r.season_id,seasonNumber:r.season_number,name:r.name,description:r.description,status:r.status,startingBalance:Number(r.starting_balance),createdAt:r.created_at,registrationOpenAt:r.registration_open_at,startedAt:r.started_at,endedAt:r.ended_at},
      player:{id:r.player_id,status:r.player_status,startingBalance:Number(r.player_starting_balance),currentPoints:totalPoints,availablePoints:Math.max(0,totalPoints-locked),lockedPoints:locked,realizedPnl:Number(r.realized_pnl||0),totalWagered:Number(r.total_wagered||0),totalWinnings:Number(r.total_winnings||0),totalLosses:Number(r.total_losses||0),predictions:Number(r.predictions||0),correctPredictions:Number(r.correct_predictions||0),incorrectPredictions:Number(r.incorrect_predictions||0),accuracy:Number(r.accuracy||0),roi:Number(r.roi||0),rank:r.current_rank||null}
    });
  }catch(e){console.error("GET /api/season/me",e);res.status(500).json({error:"Unable to load your Test Season wallet."});}
});

app.get("/api/season/matches", async (req,res)=>{
  const accountId=await requestAccountId(req);
  if(!accountId) return res.json({enrolled:false,matches:[]});
  try{
    const sq=await pool.query(`SELECT sp.season_id FROM season_players sp JOIN seasons s ON s.id=sp.season_id WHERE sp.account_id=$1 AND sp.status IN ('ACTIVE','SUSPENDED') AND s.status IN ('REGISTRATION','LIVE','PAUSED') ORDER BY CASE s.status WHEN 'LIVE' THEN 0 WHEN 'PAUSED' THEN 1 ELSE 2 END,s.created_at DESC LIMIT 1`,[accountId]);
    if(!sq.rows.length) return res.json({enrolled:false,matches:[]});
    const seasonId=sq.rows[0].season_id;
    const q=await pool.query(`SELECT sm.id,sm.season_id,sm.match_number,sm.title,sm.participant_a,sm.participant_b,sm.status,sm.winner,sm.scheduled_at,sm.started_at,sm.completed_at,sm.format,sm.description,COALESCE((SELECT COUNT(*) FROM season_markets sx WHERE sx.match_id=sm.id),0)::int AS market_count FROM season_matches sm WHERE sm.season_id=$1 ORDER BY sm.match_number ASC`,[seasonId]);
    res.set('Cache-Control','no-store');res.json({enrolled:true,matches:q.rows});
  }catch(e){console.error('GET /api/season/matches',e);res.status(500).json({error:'Unable to load season matches.'});}
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

app.post("/api/admin/matches", adminOrModerator, async (req, res) => {
  try { await assertSystemActive(); } catch (e) { return res.status(423).json({ error: e.message }); }
  const activeTest = await getActiveTestRun();
  const {
    eventName = "Ossper Weekly",
    eventDay,
    format,
    sideA,
    sideB,
    scheduledAt = null,
    closeAt = null,
    yesPrice = 0.50,
    liquidity = 100,
    marketMode = "DYNAMIC",
  } = req.body || {};

  const day = String(eventDay || "").toUpperCase();
  const fmt = String(format || "").toLowerCase();
  const a = String(sideA || "").trim();
  const b = String(sideB || "").trim();
  const event = String(eventName || "Ossper Weekly").trim();
  const price = Number(yesPrice);
  const depth = Number(liquidity);
  const mode = String(marketMode || "DYNAMIC").toUpperCase();

  if (!["FRIDAY","SATURDAY","SUNDAY"].includes(day)) return res.status(400).json({ error: "Event day must be Friday, Saturday, or Sunday." });
  if (!["1v1","2v2"].includes(fmt)) return res.status(400).json({ error: "Format must be 1v1 or 2v2." });
  if (!["DYNAMIC","FIXED"].includes(mode)) return res.status(400).json({ error: "Market mode must be Dynamic or Fixed Odds." });
  if (a.length < 2 || b.length < 2) return res.status(400).json({ error: "Both players/teams are required." });
  if (event.length < 2) return res.status(400).json({ error: "Event name is required." });
  if (!Number.isFinite(price) || price < 0.01 || price > 0.99) return res.status(400).json({ error: "YES starting price must be between 0.01 and 0.99." });
  if (!Number.isFinite(depth) || depth < 10 || depth > 1000000) return res.status(400).json({ error: "Liquidity must be between $10 and $1,000,000." });

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const matchQ = await client.query(`
      INSERT INTO matches (event_name, event_day, format, side_a_name, side_b_name, scheduled_at, status, test_run_id)
      VALUES ($1,$2,$3,$4,$5,$6,'DRAFT',$7) RETURNING *
    `, [event, day, fmt, a, b, scheduledAt || null, activeTest?.id || null]);
    const match = matchQ.rows[0];
    const question = `Will ${a} beat ${b}?`;
    const description = `${event} · ${day} ${fmt}`;
    const marketQ = await client.query(`
      INSERT INTO markets (match_id, question, description, yes_price, opening_yes_price, liquidity, status, close_at, market_type, fixed_yes_price, test_run_id)
      VALUES ($1,$2,$3,$4,$4,$5,'DRAFT',$6,$7,$8,$9) RETURNING *
    `, [match.id, question, description, price, depth, closeAt || null, mode, mode === 'FIXED' ? price : null, activeTest?.id || null]);

    await client.query(`
      INSERT INTO audit_logs (actor, action, market_id, details)
      VALUES ('admin','CREATE_MATCH_MARKET',$1,$2)
    `, [marketQ.rows[0].id, JSON.stringify({ matchId: match.id, event, day, format: fmt, sideA: a, sideB: b, scheduledAt, closeAt, yesPrice: price, liquidity: depth, marketMode: mode, testRunId: activeTest?.id || null })]);

    await client.query("COMMIT");
    res.json({ match, market: marketQ.rows[0] });
  } catch (e) {
    await client.query("ROLLBACK");
    res.status(400).json({ error: e.message });
  } finally {
    client.release();
  }
});

app.post("/api/admin/matches/:id/publish", adminOrModerator, async (req, res) => {
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

app.post("/api/admin/matches/:id/cancel", adminOrModerator, async (req, res) => {
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
  try { await assertSystemActive(); const activeTest = await getActiveTestRun(); if (activeTest) throw new Error("New markets cannot be created while a controlled test is active."); } catch (e) { return res.status(423).json({ error: e.message }); }
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

app.post("/api/admin/markets/:id/status", adminOrModerator, async (req, res) => {
  try { await assertSystemActive(); } catch (e) { return res.status(423).json({ error: e.message }); }
  const allowed = ["DRAFT","OPEN","TRADING","CLOSED","AWAITING_RESULT","RESOLVED","SETTLED","VOID"];
  const status = String(req.body?.status || "").toUpperCase();
  if (!allowed.includes(status)) return res.status(400).json({ error: "Invalid status." });
  if (req.admin?.role === "moderator" && !["OPEN","TRADING","CLOSED","AWAITING_RESULT"].includes(status)) {
    return res.status(403).json({ error: "Moderators cannot permanently settle, void, or otherwise rewrite market state." });
  }

  const id = Number(req.params.id);
  const q = await pool.query("UPDATE markets SET status=$1, updated_at=NOW() WHERE id=$2 RETURNING *", [status, id]);
  if (!q.rows.length) return res.status(404).json({ error: "Market not found." });
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

app.post("/api/admin/markets/:id/result", adminOrModerator, async (req, res) => {
  try { await assertSystemActive(); } catch (e) { return res.status(423).json({ error: e.message }); }
  const result = String(req.body?.result || "").toUpperCase();
  if (!["YES","NO","VOID"].includes(result)) return res.status(400).json({ error: "Result must be YES, NO, or VOID." });
  if (req.admin?.role === "moderator" && result === "VOID") return res.status(403).json({ error: "Moderators cannot void markets." });

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
      const costBasis = Number((Number(p.quantity) * Number(p.avg_cost)).toFixed(4));
      const pnl = Number((payout - costBasis).toFixed(4));
      const marketQuestion = m.rows[0].question;
      const payoutText = payout.toFixed(2);
      const pnlText = `${pnl >= 0 ? '+' : '-'}$${Math.abs(pnl).toFixed(2)}`;
      await createNotification(client, {
        accountId: p.account_id,
        type: 'SETTLEMENT',
        title: result === 'VOID' ? 'Position voided' : 'Position settled',
        message: `${marketQuestion} · ${p.quantity} ${p.side} contracts · Payout $${payoutText} · P/L ${pnlText}`,
        marketId: id
      });
      await client.query(
        "UPDATE positions SET quantity=0, avg_cost=0 WHERE account_id=$1 AND market_id=$2 AND side=$3",
        [p.account_id, id, p.side]
      );
    }

    const wagers = await client.query("SELECT * FROM wagers WHERE market_id=$1 AND status IN ('PENDING','ACCEPTED') FOR UPDATE", [id]);
    for (const w of wagers.rows) {
      if (w.status === 'PENDING' || result === 'VOID') {
        const acctQ = await client.query("SELECT balance FROM accounts WHERE id=$1 FOR UPDATE", [w.creator_account_id]);
        const before = Number(acctQ.rows[0].balance);
        const after = Number((before + Number(w.amount)).toFixed(4));
        await client.query("UPDATE accounts SET balance=$1 WHERE id=$2", [after, w.creator_account_id]);
        await addLedgerEntry(client, { accountId:w.creator_account_id, entryType:'WAGER_REFUND', amount:Number(w.amount), balanceBefore:before, balanceAfter:after, marketId:id, reference:`WAGER_${w.id}`, details:{wagerId:w.id, reason:result === 'VOID' ? 'VOID_MARKET' : 'UNACCEPTED'}, testRunId:w.test_run_id });
        if (result === 'VOID') {
          const oppQ = await client.query("SELECT balance FROM accounts WHERE id=$1 FOR UPDATE", [w.opponent_account_id]);
          const ob = Number(oppQ.rows[0].balance), oa = Number((ob + Number(w.amount)).toFixed(4));
          await client.query("UPDATE accounts SET balance=$1 WHERE id=$2", [oa,w.opponent_account_id]);
          await addLedgerEntry(client, { accountId:w.opponent_account_id, entryType:'WAGER_REFUND', amount:Number(w.amount), balanceBefore:ob, balanceAfter:oa, marketId:id, reference:`WAGER_${w.id}`, details:{wagerId:w.id, reason:'VOID_MARKET'}, testRunId:w.test_run_id });
        }
        await client.query("UPDATE wagers SET status='VOID', settled_at=NOW() WHERE id=$1", [w.id]);
        continue;
      }
      const creatorWon = w.creator_side === result;
      const winner = creatorWon ? w.creator_account_id : w.opponent_account_id;
      const payout = Number((Number(w.amount) * 2).toFixed(4));
      const acctQ = await client.query("SELECT balance FROM accounts WHERE id=$1 FOR UPDATE", [winner]);
      const before = Number(acctQ.rows[0].balance), after = Number((before + payout).toFixed(4));
      await client.query("UPDATE accounts SET balance=$1 WHERE id=$2", [after,winner]);
      await addLedgerEntry(client,{accountId:winner,entryType:'WAGER_PAYOUT',amount:payout,balanceBefore:before,balanceAfter:after,marketId:id,reference:`WAGER_${w.id}`,details:{wagerId:w.id,payout,result},testRunId:w.test_run_id});
      await client.query("UPDATE wagers SET status='SETTLED', winner_account_id=$1, settled_at=NOW() WHERE id=$2",[winner,w.id]);
      await createNotification(client,{accountId:winner,type:'WAGER',title:'Wager won',message:`You won a $${payout.toFixed(2)} payout on ${m.rows[0].question}.`,marketId:id});
      const loser=creatorWon?w.opponent_account_id:w.creator_account_id;
      await createNotification(client,{accountId:loser,type:'WAGER',title:'Wager settled',message:`Your $${Number(w.amount).toFixed(2)} wager settled on ${m.rows[0].question}.`,marketId:id});
    }

    await client.query("UPDATE markets SET status='SETTLED', updated_at=NOW() WHERE id=$1", [id]);
    const matchQ = await client.query("SELECT match_id FROM markets WHERE id=$1", [id]);
    if (matchQ.rows[0]?.match_id) await client.query("UPDATE matches SET status='COMPLETE', updated_at=NOW() WHERE id=$1", [matchQ.rows[0].match_id]);
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

app.get("/api/admin/matches", adminOnly, async (_req, res) => {
  const q = await pool.query(`
    SELECT mt.*, m.id AS market_id, m.status AS market_status, m.yes_price, m.close_at, m.result,
      COALESCE((SELECT SUM(gross) FROM trades t WHERE t.market_id=m.id),0) AS volume,
      COALESCE((SELECT COUNT(*) FROM trades t WHERE t.market_id=m.id),0) AS trade_count
    FROM matches mt
    LEFT JOIN markets m ON m.match_id=mt.id
    ORDER BY mt.id DESC
  `);
  res.json(q.rows);
});

app.get("/api/admin/audit", adminOnly, async (req, res) => {
  const page = Math.max(1, Number.parseInt(req.query.page, 10) || 1);
  const pageSize = Math.min(100, Math.max(10, Number.parseInt(req.query.pageSize, 10) || 40));
  const action = String(req.query.action || '').trim();
  const actor = String(req.query.actor || '').trim();
  const marketId = Number.parseInt(req.query.marketId, 10);
  const where = [];
  const params = [];
  if (action) { params.push(`%${action}%`); where.push(`action ILIKE $${params.length}`); }
  if (actor) { params.push(`%${actor}%`); where.push(`actor ILIKE $${params.length}`); }
  if (Number.isInteger(marketId) && marketId > 0) { params.push(marketId); where.push(`market_id=$${params.length}`); }
  const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';
  const countQ = await pool.query(`SELECT COUNT(*)::int AS total FROM audit_logs ${whereSql}`, params);
  const total = Number(countQ.rows[0].total || 0);
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const safePage = Math.min(page, pages);
  const offset = (safePage - 1) * pageSize;
  const rows = await pool.query(`SELECT * FROM audit_logs ${whereSql} ORDER BY id DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`, [...params, pageSize, offset]);
  res.json({ rows: rows.rows, page: safePage, pageSize, pages, total });
});



app.get("/api/admin/test", adminOrModerator, async (_req, res) => {
  const run = await getActiveTestRun();
  if (!run) return res.json({ active:false });
  const members = await pool.query(`SELECT a.id, a.discord_id, a.display_name, a.balance FROM test_run_members tm JOIN accounts a ON a.id=tm.account_id WHERE tm.test_run_id=$1 ORDER BY tm.added_at`, [run.id]);
  const stats = await pool.query(`SELECT COUNT(*)::int AS trades, COALESCE(SUM(gross),0) AS volume FROM trades WHERE test_run_id=$1`, [run.id]);
  const audits = await pool.query(`SELECT COUNT(*)::int AS events FROM audit_logs WHERE test_run_id=$1`, [run.id]);
  const wagers = await pool.query(`SELECT COUNT(*)::int AS count, COALESCE(SUM(amount) FILTER (WHERE status IN ('ACCEPTED','SETTLED')),0) AS staked FROM wagers WHERE test_run_id=$1`, [run.id]);
  return res.json({active:true, run, members:members.rows, stats:{trades:stats.rows[0].trades,volume:Number(stats.rows[0].volume),events:audits.rows[0].events,wagers:Number(wagers.rows[0].count||0),wagered:Number(wagers.rows[0].staked||0)}});
});

app.get("/api/admin/test/users", adminOrModerator, async (req,res)=>{
  const q=String(req.query.q||'').trim().slice(0,80);
  const params=[]; let where="WHERE discord_id IS NOT NULL";
  if(q){ params.push(`%${q}%`); where+=" AND (display_name ILIKE $1 OR discord_id ILIKE $1)"; }
  const rows=await pool.query(`SELECT id,discord_id,display_name,avatar_url FROM accounts ${where} ORDER BY LOWER(COALESCE(display_name,'')), discord_id LIMIT 20`,params);
  res.set("Cache-Control","no-store"); res.json({users:rows.rows});
});
app.post("/api/admin/test/start", adminOnly, async (req, res) => {
  try { await assertSystemActive(); } catch (e) { return res.status(423).json({error:e.message}); }
  const existing = await getActiveTestRun();
  if (existing) return res.status(409).json({error:"A test run is already active."});
  const discordIds = Array.isArray(req.body?.discordIds) ? req.body.discordIds.map(String).map(s=>s.trim()).filter(Boolean) : [];
  if (!discordIds.length) return res.status(400).json({error:"Add at least one Discord user ID before starting the test."});
  const label = String(req.body?.label || "Ossper Demo Test").slice(0,120);
  const client = await pool.connect();
  const runId = crypto.randomUUID();
  try {
    await client.query("BEGIN");
    const accounts = await client.query("SELECT id,discord_id FROM accounts WHERE discord_id = ANY($1::text[])", [discordIds]);
    if (accounts.rows.length !== discordIds.length) {
      const found = new Set(accounts.rows.map(r=>r.discord_id));
      const missing = discordIds.filter(x=>!found.has(x));
      throw new Error(`These Discord accounts are not linked to Ossper yet: ${missing.join(', ')}`);
    }
    await client.query("INSERT INTO test_runs (id,status,label,started_by) VALUES ($1,'ACTIVE',$2,$3)", [runId,label,req.admin?.accountId || req.admin?.discordId || 'admin']);
    for (const a of accounts.rows) await client.query("INSERT INTO test_run_members (test_run_id,account_id) VALUES ($1,$2)",[runId,a.id]);
    await snapshotTestState(client, runId, accounts.rows.map(a=>a.id));
    for (const a of accounts.rows) {
      const beforeQ = await client.query("SELECT balance FROM accounts WHERE id=$1 FOR UPDATE", [a.id]);
      const before = Number(beforeQ.rows[0].balance);
      await client.query("UPDATE accounts SET balance=500.00 WHERE id=$1", [a.id]);
      await client.query("DELETE FROM positions WHERE account_id=$1", [a.id]);
      await client.query(`INSERT INTO ledger_entries (account_id,entry_type,amount,balance_before,balance_after,reference,details,test_run_id) VALUES ($1,'TEST_START_RESET',$2,$3,500.00,$4,$5,$6)`, [a.id, Number((500-before).toFixed(4)), before, `TEST_START_${runId}`, JSON.stringify({runId}), runId]);
    }
    await client.query(`INSERT INTO audit_logs (actor,action,details,test_run_id) VALUES ($1,'TEST_STARTED',$2,$3)`, [req.admin?.accountId || req.admin?.discordId || 'admin', JSON.stringify({runId,label,members:accounts.rows.length}), runId]);
    await client.query("COMMIT");
    res.json({ok:true,runId});
  } catch(e){await client.query("ROLLBACK");res.status(400).json({error:e.message});} finally{client.release();}
});

app.post("/api/admin/test/end", adminOnly, async (req, res) => {
  const run = await getActiveTestRun();
  if (!run) return res.status(404).json({error:"No active test run."});
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const stats = await client.query("SELECT COUNT(*)::int AS trades, COALESCE(SUM(gross),0) AS volume FROM trades WHERE test_run_id=$1", [run.id]);
    const createdMarkets = await client.query("SELECT id FROM markets WHERE test_run_id=$1", [run.id]);
    for (const cm of createdMarkets.rows) {
      await client.query("DELETE FROM positions WHERE market_id=$1", [cm.id]);
      await client.query("UPDATE markets SET status='VOID', result='VOID', updated_at=NOW() WHERE id=$1", [cm.id]);
    }
    await client.query("UPDATE wagers SET status='VOID', settled_at=NOW() WHERE test_run_id=$1 AND status IN ('PENDING','ACCEPTED')", [run.id]);
    await client.query("UPDATE matches SET status='CANCELLED', updated_at=NOW() WHERE test_run_id=$1", [run.id]);
    await restoreTestState(client, run.id);
    await client.query("UPDATE test_runs SET status='ENDED', ended_by=$1, ended_at=NOW() WHERE id=$2", [req.admin?.accountId || req.admin?.discordId || 'admin', run.id]);
    await client.query(`INSERT INTO audit_logs (actor,action,details,test_run_id) VALUES ($1,'TEST_ENDED',$2,$3)`, [req.admin?.accountId || req.admin?.discordId || 'admin', JSON.stringify({runId:run.id,trades:Number(stats.rows[0].trades),volume:Number(stats.rows[0].volume)}), run.id]);
    await client.query("COMMIT");
    res.json({ok:true,runId:run.id,trades:Number(stats.rows[0].trades),volume:Number(stats.rows[0].volume)});
  } catch(e){await client.query("ROLLBACK");res.status(400).json({error:e.message});} finally{client.release();}
});

app.post("/api/admin/test/funds", adminOnly, async (req,res)=>{
  const run=await getActiveTestRun(); if(!run)return res.status(404).json({error:"No active test run."});
  const discordId=String(req.body?.discordId||'').trim(); const amount=Number(req.body?.amount);
  if(!/^\d{15,22}$/.test(discordId)||!Number.isFinite(amount)||amount<=0||amount>100000)return res.status(400).json({error:"Enter a valid Discord ID and amount up to $100,000."});
  const q=await pool.query("SELECT a.id,a.balance FROM accounts a JOIN test_run_members tm ON tm.account_id=a.id WHERE tm.test_run_id=$1 AND a.discord_id=$2",[run.id,discordId]); if(!q.rows.length)return res.status(404).json({error:"That account is not enrolled in the active test."});
  const before=Number(q.rows[0].balance),after=Number((before+amount).toFixed(4)); await pool.query("UPDATE accounts SET balance=$1 WHERE id=$2",[after,q.rows[0].id]);
  await pool.query(`INSERT INTO ledger_entries(account_id,entry_type,amount,balance_before,balance_after,reference,details,test_run_id) VALUES($1,'TEST_FUNDS',$2,$3,$4,$5,$6,$7)`,[q.rows[0].id,amount,before,after,`TEST_FUNDS_${run.id}`,JSON.stringify({runId:run.id,discordId}),run.id]);
  await testAudit(req.admin?.accountId||req.admin?.discordId||'admin','TEST_FUNDS_ADDED',{discordId,amount},run.id);
  res.json({ok:true,balance:after});
});

app.post("/api/admin/test/reset-account", adminOnly, async (req,res)=>{
  const run=await getActiveTestRun(); if(!run)return res.status(404).json({error:"No active test run."});
  const discordId=String(req.body?.discordId||'').trim();
  const snap=await pool.query("SELECT account_id,balance FROM test_account_snapshots s JOIN accounts a ON a.id=s.account_id WHERE s.test_run_id=$1 AND a.discord_id=$2",[run.id,discordId]); if(!snap.rows.length)return res.status(404).json({error:"That account is not enrolled in the active test."});
  const accountId=snap.rows[0].account_id, target=Number(snap.rows[0].balance); const currentQ=await pool.query("SELECT balance FROM accounts WHERE id=$1",[accountId]); const before=Number(currentQ.rows[0].balance); await pool.query("UPDATE accounts SET balance=$1 WHERE id=$2",[target,accountId]); await pool.query("DELETE FROM positions WHERE account_id=$1",[accountId]);
  const ps=await pool.query("SELECT market_id,side,quantity,avg_cost,realized_pnl FROM test_position_snapshots WHERE test_run_id=$1 AND account_id=$2",[run.id,accountId]); for(const p of ps.rows) await pool.query("INSERT INTO positions(account_id,market_id,side,quantity,avg_cost,realized_pnl) VALUES($1,$2,$3,$4,$5,$6)",[accountId,p.market_id,p.side,p.quantity,p.avg_cost,p.realized_pnl]);
  await pool.query(`INSERT INTO ledger_entries(account_id,entry_type,amount,balance_before,balance_after,reference,details,test_run_id) VALUES($1,'TEST_ACCOUNT_RESET',$2,$3,$4,$5,$6,$7)`,[accountId,Number((target-before).toFixed(4)),before,target,`TEST_RESET_${run.id}`,JSON.stringify({runId:run.id,discordId}),run.id]);
  await testAudit(req.admin?.accountId||req.admin?.discordId||'admin','TEST_ACCOUNT_RESET',{discordId,before,after:target},run.id); res.json({ok:true,balance:target});
});

app.post("/api/admin/test/reset-all", adminOnly, async (req,res)=>{
  const run=await getActiveTestRun(); if(!run)return res.status(404).json({error:"No active test run."});
  const members=await pool.query("SELECT a.id,a.discord_id FROM test_run_members tm JOIN accounts a ON a.id=tm.account_id WHERE tm.test_run_id=$1",[run.id]);
  for(const a of members.rows){
    const targetQ=await pool.query("SELECT balance FROM test_account_snapshots WHERE test_run_id=$1 AND account_id=$2",[run.id,a.id]);
    const currentQ=await pool.query("SELECT balance FROM accounts WHERE id=$1",[a.id]);
    const before=Number(currentQ.rows[0].balance); const target=500;
    await pool.query("UPDATE accounts SET balance=$1 WHERE id=$2",[target,a.id]); await pool.query("DELETE FROM positions WHERE account_id=$1",[a.id]);
    await pool.query(`INSERT INTO ledger_entries(account_id,entry_type,amount,balance_before,balance_after,reference,details,test_run_id) VALUES($1,'TEST_RESET_ALL',$2,$3,$4,$5,$6,$7)`,[a.id,Number((target-before).toFixed(4)),before,target,`TEST_RESET_ALL_${run.id}`,JSON.stringify({runId:run.id,originalBalance:targetQ.rows[0]?.balance}),run.id]);
  }
  await testAudit(req.admin?.accountId||req.admin?.discordId||'admin','TEST_ALL_ACCOUNTS_RESET',{members:members.rowCount},run.id);
  res.json({ok:true,reset:members.rowCount});
});

app.get("/api/admin/test/history", adminOrModerator, async (_req,res)=>{
  try{
    const runs=await pool.query(`SELECT tr.id,tr.status,tr.label,tr.started_by,tr.started_at,tr.ended_by,tr.ended_at,
      (SELECT COUNT(*) FROM test_run_members tm WHERE tm.test_run_id=tr.id)::int AS members
      FROM test_runs tr ORDER BY tr.started_at DESC LIMIT 25`);
    const rows=[];
    for(const r of runs.rows){
      const q=await pool.query(`SELECT COUNT(*)::int AS trades, COALESCE(SUM(gross),0) AS volume FROM trades WHERE test_run_id=$1`,[r.id]);
      const e=await pool.query(`SELECT COUNT(*)::int AS events FROM audit_logs WHERE test_run_id=$1`,[r.id]);
      const w=await pool.query(`SELECT COUNT(*)::int AS wagers, COALESCE(SUM(amount) FILTER (WHERE status IN ('ACCEPTED','SETTLED')),0) AS wagered FROM wagers WHERE test_run_id=$1`,[r.id]);
      const startMs=new Date(r.started_at).getTime(), endMs=r.ended_at?new Date(r.ended_at).getTime():Date.now();
      rows.push({...r,trades:Number(q.rows[0]?.trades||0),volume:Number(q.rows[0]?.volume||0),events:Number(e.rows[0]?.events||0),wagers:Number(w.rows[0]?.wagers||0),wagered:Number(w.rows[0]?.wagered||0),durationSeconds:Math.max(0,Math.round((endMs-startMs)/1000))});
    }
    res.set('Cache-Control','no-store'); res.json(rows);
  }catch(e){
    console.error('test history error:',e);
    res.status(500).json({error:'Unable to load recent test performance.'});
  }
});

app.get("/admin-test", (_req, res) => res.sendFile(path.join(publicDir, "test-admin.html")));
app.get("/admin", (_req, res) => {
  const adminPath = path.join(publicDir, "admin.html");
  try {
    let html = fs.readFileSync(adminPath, "utf8");
    const testButton = `<a href="/admin-test" style="position:fixed;top:18px;right:18px;z-index:9999;text-decoration:none;border:1px solid #527bb1;background:#152943;color:#eaf2ff;border-radius:9px;padding:10px 14px;font:700 13px Inter,ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;box-shadow:0 8px 24px rgba(0,0,0,.25)">🧪 Test Control</a>`;
    if (!html.includes('href="/admin-test"')) html = html.replace("<body>", `<body>${testButton}`);
    res.type("html").send(html);
  } catch (e) {
    res.sendFile(adminPath);
  }
});
app.use((_req, res) => res.sendFile(path.join(publicDir, "index.html")));

initDb()
  .then(() => {
    app.listen(PORT, () => console.log(`Ossper Markets listening on ${PORT}`));
  })
  .catch(err => {
    console.error("Database initialization failed:", err);
    process.exit(1);
  });
