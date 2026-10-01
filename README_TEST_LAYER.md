# Ossper Controlled Test Layer

This patch is additive to the existing Ossper v1.3 backend.

Files in this package:
- `server.js` — backend with controlled test-run support and additive PostgreSQL migrations.
- `test-admin.html` — separate test-control page at `/admin-test`.

Important deployment rule:
- Replace the deployed `server.js` with this `server.js`.
- Upload `test-admin.html` alongside it.
- Do NOT replace `index.html` or the existing `admin.html` with this package. That preserves the current public/admin UI.
- No database wipe is required.

Test behavior:
- Owner/admin starts a named test with selected Discord user IDs.
- Selected accounts begin the test at $500 with active positions cleared for the run.
- Original balances/positions and market/match state are snapshotted.
- Test trades, test funding, test resets, and test audit events are tagged with the test run ID.
- Non-enrolled accounts are blocked from trading while a controlled test is active.
- New markets/matches cannot be created during a controlled test.
- Ending the test restores enrolled account balances/positions and market/match state.
- Test records remain in PostgreSQL for analysis.
