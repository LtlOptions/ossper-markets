# Ossper Markets — Phase 4 Tournament UX

Version 2.2.0.

This pass focuses on the public tournament experience without rebuilding the market engine.

## Included

- Tournament page organized around **Tournament → Matches → Markets**.
- Entire tournament cards are clickable and keyboard accessible.
- Tournament overview modal with:
  - live/upcoming/completed status
  - players
  - matches
  - markets
  - trading volume
  - match list
  - recorded results for completed matches
- Match rows open the relevant market experience.
- Tournament filters: All / Live / Upcoming / Completed.
- Test-run markets are excluded from the normal public tournament presentation; Test Season remains the isolated place for sandbox events.
- Existing market/trading endpoints and settlement logic are preserved.
- No database reset, deletion, or destructive migration.

## Deliberately deferred

Portfolio chart coordinate work, notification mutual-close behavior, admin/test theme audit, and other Phase 4 polish items remain separate follow-up steps so the tournament change can be tested independently.

## v2.2.1 — Interactive How It Works / Demo Access
- Promoted How It Works to a primary Home action beside Explore Markets.
- Converted How It Works information panels into interactive actions.
- Added guided highlights for Markets, Prices, Buying & Selling, Position Status, Lifecycle, Depth, Notifications, Wagers, Simulation Mode, and Activity.
- Notification guide step highlights the bell and completes when the bell is opened.
- Added an on-demand interactive demo market launched from How It Works.
- Removed the always-visible demo market from normal Home, Markets, Tournaments, and wager pickers; it remains available through the guide.
- Preserved existing virtual-money trading flow and backend logic.
