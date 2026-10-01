# Ossper Markets v0.7

Virtual-money community prediction market for Ossper tournament outcomes.

## v0.7 — Tournament match markets
- Admin can create Friday 1v1, Saturday 2v2, and Sunday 1v1 match markets.
- Each match stores event name, day, format, side A, side B, scheduled time, and trading close time.
- New match markets start as private DRAFTs and can be published from the admin panel.
- Public users see published markets with player/team names on the YES/NO sides.
- Trading close time is enforced server-side; expired markets are closed automatically when the market API is read or a trade is attempted.
- Admin can publish, close, await result, resolve, and settle match markets.
- Draft matches can be cancelled before publication.
- Existing v0.6 standalone/demo markets remain supported.
- Audit logs record match creation, publication, status changes, and settlement actions.

## Existing engine
- PostgreSQL-backed accounts, positions, trades, markets, matches, and audit logs.
- Server-authoritative virtual balance.
- Buy/sell with a 1% fee.
- Simple automated price impact while preserving YES + NO = $1.00.
- Winning contracts settle at $1; losing contracts at $0.
- Temporary admin-key authentication. Discord OAuth should replace this before public launch.

## Railway variables
Required:
- `DATABASE_URL` — provided by Railway Postgres.
- `OSSPER_ADMIN_KEY` — choose a long random secret. Never put it in GitHub and never send it in chat.

## Important
This is not a real-money system and is not legal/regulatory ready. Do not connect payments or real money without a separate security/legal review.
