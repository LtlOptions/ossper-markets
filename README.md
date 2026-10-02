# Ossper Markets v1.6.3 — Sandbox + Community UX

Community prediction market for tournament events. Virtual money only.

## v1.6 changes
- Added a central Home page with upcoming events, highlights/activity, navigation cards, and Discord community entry point.
- Settings now open naturally on desktop hover and remain tap-friendly on mobile.
- Added settlement notifications with payout and realized P/L details.
- Added optional browser notifications while Ossper is open in a background tab.
- Added fixed-odds binary markets. Fixed odds remain locked at the opening probability until trading closes.
- Added Owner / Admin / Moderator / User role structure with backend-enforced moderator permissions.
- Moderators can create/publish/cancel tournaments and perform routine market lifecycle actions, but cannot manage roles, freeze the system, fund accounts, or manage test infrastructure.
- Test Control now supports a searchable linked-Discord tester directory.
- Controlled tests can create sandbox tournament matches while a test is active.
- Test-created markets/matches are tagged to the run, isolated from non-test users, and marked VOID/CANCELLED when the test ends while test trade/audit history is retained.
- Fixed Test Control history loading so completed runs render instead of staying on Loading.
- Added a Test Run audit filter for isolating sandbox events.
- Added a fixed-odds preview that shows locked YES/NO decimal odds from the opening probability.
- Improved Settings hover behavior and added stronger market/Home presentation for fixed-odds markets.
- Fixed Admin audit API/UI response mismatch and restored paginated/filterable audit history.
- Added defensive JSON/error handling and debounced quote requests to prevent spinner/rapid-input rate-limit errors.
- No database wipe. All database changes are additive migrations.

## Existing architecture preserved
- PostgreSQL balances, positions, trades, ledger, sessions, audit logs, system freeze, Discord OAuth, and controlled test snapshots.
- Server-authoritative balances and settlement.
- Virtual-money only.

## Required environment variables
- DATABASE_URL
- OSSPER_ADMIN_KEY
- DISCORD_CLIENT_ID
- DISCORD_CLIENT_SECRET
- DISCORD_REDIRECT_URI
- OSSPER_AUTH_SECRET

Virtual-money demo only. Do not treat this as a real-money platform.

- v1.6.3: added a compact market overview modal with open/close times, live/fixed odds, volume/depth, positions, and Buy/Sell shortcuts; clicking a market opens the overview without navigating away.


### v1.6.5 — Tournament filters & results archive
- Markets can filter by day and 1v1/2v2 format.
- Tournament calendar filters by day and format.
- Optional Include past results filter reveals completed tournaments for the selected day/format.
- Past tournament cards expose result hints and open the existing tournament overview/results modal.
- v1.6.4 visual polish is included.
