# Ossper Controlled Test Layer

The current v1.7 test layer is additive and designed as a sandbox around the production database.

### Test behavior
- Search linked Discord accounts by display name or Discord ID and select testers.
- Selected accounts begin at $500 with pre-test balances/positions snapshotted.
- Test trades, test funds, resets, and audit events are tagged with the test-run ID.
- Non-enrolled accounts cannot trade while a controlled test is active.
- Test participants can create tournament matches while the test is active.
- Test-created matches/markets are tagged to the active test run and isolated from normal users.
- Ending the test restores participating account state and pre-existing market/match state.
- Test-created markets are marked VOID and their test positions are removed; test trade/audit records remain for analysis.
- Completed test history is retained in PostgreSQL.
- No database wipe is required.

### Important
Deploy the complete package together. Do not mix the older v1.3 test-layer files with the v1.7 production UI.


### Moderator behavior
Moderators may create and publish tournament matches while a test run is active; those matches are automatically tagged to the active test run. Starting/ending tests and test funding/reset operations remain Owner/Admin only.
