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
