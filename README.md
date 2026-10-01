# Ossper Markets v1.3.0

Community prediction market for tournament events. Virtual money only.

## v1.3 changes
- Discord accounts can be authorized as Ossper admins using server-side `admin_roles`.
- First owner can be bootstrapped once using the existing `OSSPER_ADMIN_KEY` while already signed into Ossper with Discord.
- Owner can grant/revoke the `admin` role by Discord user ID.
- Admin API accepts either a valid legacy admin-key session or a valid Discord session with an active admin role.
- Admin actions remain server-authoritative and existing PostgreSQL data is preserved.
- Discord admin login returns to `/admin`.
- Legacy admin key remains available as an emergency fallback; it is not exposed to the browser except through the existing admin login form.

## Required environment variables
- `DATABASE_URL`
- `OSSPER_ADMIN_KEY`
- `DISCORD_CLIENT_ID`
- `DISCORD_CLIENT_SECRET`
- `DISCORD_REDIRECT_URI`
- `OSSPER_AUTH_SECRET`

No database wipe is required. The server creates the additive `admin_roles` table automatically.
