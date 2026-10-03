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


## v2.2.2 — Guided Demo / Dropdown / Guide Navigation Hotfix
- Settings menu is layered above the notification panel so desktop Preferences/Admin/Help controls remain usable.
- Notification dropdown is click-open only; the old invisible hover bridge was removed so it cannot create a large transparent hitbox or unexpectedly reopen.
- Account/mobile navigation layering is explicitly separated from notification UI.
- Added a persistent “Back to How It Works” control when a user enters another area from the guide.
- Interactive demo now gives a short visual cursor walkthrough of BUY → quote review, then hands control to the user.
- The demo walkthrough never submits a trade automatically.
- Trade confirmation is elevated above the demo modal so the quote/confirmation screen is fully interactive.
- No database or market-engine changes.
