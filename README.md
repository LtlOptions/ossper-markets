# Ossper Markets v0.8

Ossper Markets is a virtual-money community prediction market for tournament outcomes.

## v0.8 changes
- Sleek responsive market UI with one global portfolio/balance section.
- Navigation for Markets, Tournaments, Activity, Portfolio, Settings, and Admin.
- 3-decimal contract prices and price-movement indicators.
- Per-market configurable opening YES probability.
- Per-market configurable virtual liquidity / market depth.
- Liquidity-aware pricing: larger depth requires more traded dollars to move probability.
- Server-side quote endpoint with estimated average execution price, fee, and price movement.
- Trade modal replaces browser prompts and previews estimated debit/credit.
- Existing v0.7 database is migrated in place; no database reset required.

## Market depth
Liquidity is an approximate virtual market-depth control. A $50-depth market will move more from a $10 trade than a $1,000-depth market. Opening probability and depth are independent.

## Safety
Virtual money only. This build is not real-money ready and should not be used to accept wagers or payments. Discord authentication, stronger account security, player restrictions, surveillance controls, and legal/regulatory review are still required before any public or real-money use.

## Railway variables
- `DATABASE_URL`
- `OSSPER_ADMIN_KEY`

Start with `npm start`.
