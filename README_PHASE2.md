# Ossper Markets v1.9.0 — Test Season Phase 2

Phase 2 adds enrolled Test Season players and isolated OSSPER POINTS wallets.

- Normal `accounts.balance` is never modified by season enrollment.
- Each enrolled player gets a season-specific wallet row and initial wallet ledger entry.
- Season wallet fields live in `season_players`; season events are recorded in `season_wallet_entries`.
- Season stats are initialized in `season_stats`.
- Admin enrollment, removal, suspension, restoration, and re-enrollment are audited.
- Player Test Season page shows season points, available/locked points, profit, predictions, accuracy, and rank.
- Persistent `SIMULATION · NO REAL MONEY` badge appears for enrolled players.
- Season trading/settlement remains intentionally disabled until later phases.
