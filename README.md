# Ossper Markets v1.2.1

Small authentication patch for Ossper Markets v1.2.

## v1.2.1 fixes
- Fixed logout authentication state: a browser account ID can no longer keep a Discord session authenticated after the server session is deleted.
- Logout now waits for the server to confirm session deletion before updating the UI.
- Logout failure is surfaced instead of silently reloading.
- Removed the accidental `menu` CSS class from the Sign out button.
- No database wipe; existing markets, accounts, positions, trades, ledger, sessions, and audit data are preserved.

## Discord environment variables
- `DISCORD_CLIENT_ID`
- `DISCORD_CLIENT_SECRET`
- `DISCORD_REDIRECT_URI`
- `OSSPER_AUTH_SECRET`

Virtual money only.
