# Ossper Markets v1.2

Virtual-money community prediction market for Ossper tournament events.

## v1.2 additions
- Optional Discord OAuth identity and server-side sessions.
- Guest mode remains available for testing.
- Existing guest account can be linked to the Discord identity used during sign-in.
- Account identity is server-authoritative once a session cookie exists.
- Session tokens are stored as hashes in PostgreSQL and expire after 30 days.
- Discord OAuth state is signed and short-lived.
- Browser-level duplicate confirmation prompt removed; Ossper's own trade confirmation/quote is the confirmation layer.
- Existing PostgreSQL data is preserved; migrations are additive.

## Discord configuration (Railway variables)
Set these server-side in Railway Variables before enabling Discord login:
- `DISCORD_CLIENT_ID`
- `DISCORD_CLIENT_SECRET`
- `DISCORD_REDIRECT_URI` = `https://ossper-markets-production.up.railway.app/auth/discord/callback`
- `OSSPER_AUTH_SECRET` = a long random secret distinct from the admin key

In the Discord Developer Portal, add the exact redirect URI above to the OAuth2 redirect URLs and use the `identify` scope. Never put the client secret in frontend code or GitHub.

## Existing infrastructure
- Frontend: `index.html`
- Backend: `server.js` on Railway
- Database: PostgreSQL
- Admin: `admin.html`
- Virtual money only. No real-money functionality is enabled.
