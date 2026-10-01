# Ossper Markets v0.6

Virtual-money community prediction market.

## What's new
- PostgreSQL-backed accounts, positions, trades, markets, and audit logs.
- Server-authoritative balance and positions.
- Buy and sell with a 1% trading fee.
- Simple automated price impact while preserving YES + NO = $1.00.
- Market lifecycle/status controls.
- Admin market creation, open/close controls, result entry, settlement, and audit log.
- Temporary admin-key authentication. Discord OAuth should replace this before public launch.
- Still virtual money only.

## Railway variables
Required:
- `DATABASE_URL` — provided by Railway Postgres.
- `OSSPER_ADMIN_KEY` — choose a long random secret. Never put it in GitHub and never send it in chat.

## Important
This is not a real-money system and is not legal/regulatory ready. Do not connect payments or real money without a separate security/legal review.
