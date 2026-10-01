# Ossper Markets v1.5.0 — Demo Ready

Community prediction market for tournament events. Virtual money only.

## v1.5 changes
- User help / onboarding guide explaining markets, prices, positions, lifecycle, depth, notifications, freeze controls, and virtual money.
- First-visit welcome card with a link to the guide.
- Persistent in-app notification bell for trading close, awaiting-result, and settlement events.
- Tournament markets can be binary 1v1/2v2 or Pick a Winner with 3–20 outcomes.
- Multi-outcome prices and positions are server-authoritative and settle to $1 for the winning outcome.
- Settings expanded with extra background palette colors and custom six-digit hex background color.
- Admin audit log is paginated and filterable by action, actor, and market ID.
- Existing admin dashboard, Discord roles, emergency freeze, PostgreSQL ledger, and audit trail preserved.
- Additive PostgreSQL migrations only; no database wipe required.

## Required environment variables
- DATABASE_URL
- OSSPER_ADMIN_KEY
- DISCORD_CLIENT_ID
- DISCORD_CLIENT_SECRET
- DISCORD_REDIRECT_URI
- OSSPER_AUTH_SECRET

Virtual-money demo only. Do not treat this as a real-money platform.
