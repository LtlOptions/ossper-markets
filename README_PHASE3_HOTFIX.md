# Ossper v2.0.1 — Phase 3 match hotfix

Fixes based on Phase 3 testing:

- Adds the missing `season_matches.scheduled_at` additive migration so scheduled match times persist safely on existing databases.
- Fixes admin match rendering from `[object Object]` to enrolled player display names.
- Keeps participant IDs authoritative; display names are presentation only.
- Makes datetime-local conversion explicit and timezone-safe for the browser session.
- Player Test Season pages now refresh season matches every 10 seconds while the Season page is open, so newly created matches appear without a manual reload.
- Match-load errors now re-render the season page instead of silently leaving stale/empty content.

No tables are dropped, truncated, deleted, or reset. No existing balances are changed by this hotfix.
