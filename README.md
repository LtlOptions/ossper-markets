# Ossper Markets v1.7.1 — Sandbox + Community UX

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
- Fixed Test Control history loading/caching behavior.
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


## v1.7.0 — Mobile auth, sandbox moderator tools, and visual system
- Mobile-safe Discord OAuth callback: signed state no longer depends on a state cookie surviving the Discord handoff.
- Owner/admin role assignment now searches the linked Discord directory by display name or ID.
- Active test control is visible to moderators, but starting/ending tests and funding/reset infrastructure remain Owner/Admin-only.
- Moderators can create sandbox tournament drafts directly from Test Control while a test is active.
- Added explicit User mode / Mod-Test mode navigation.
- Added 10 interface themes and shared theme propagation to Admin/Test Control.
- Settings reorganized into collapsible Appearance, Dashboard, Trading, and Notifications groups.
- Main dashboard cards use the glass surface system more consistently instead of a wall of opaque blue.
- Admin live matches are grouped by tournament to reduce clutter.
- User-facing “Resolve” wording changed to “Record winner” where applicable.
- Existing database state is preserved; no DROP/TRUNCATE operations are used.


## v1.7.1 — Role middleware, mode menu, and settings polish
- Fixed elevated admin/moderator routes so Discord-authenticated Owner/Admin/Moderator sessions are actually loaded before permission checks.
- Fixed Discord OAuth callback handling when mobile drops the temporary OAuth state cookie.
- Interface theme, accent color, and surface style are now compact dropdown selectors instead of large button walls.
- Settings hover menu now closes when the pointer leaves the menu area while remaining tap-friendly on mobile.
- Account dropdown now shows the current access mode with icons and direct User / Mod-Test / Admin switching when permitted.
- Admin and Test Control inherit the saved interface theme, accent, glass/solid surface choice, and custom background.
- Test Control now shows the authenticated Ossper role/source so permission problems are immediately visible.
- No database wipe, DROP, or TRUNCATE operations added.
