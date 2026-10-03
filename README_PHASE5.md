# Ossper Markets — Phase 5 Competitive Engine

Version 2.3.0.

This patch starts the competitive Ossper layer without replacing the existing market/trading system.

## Included

### Tournament / bracket engine
- Automatic 1v1 single-elimination bracket generation for 2/4/8/16/32 active Test Season players.
- Round and bracket-slot metadata on season matches.
- Winner advancement into the next round is server-authoritative.
- Matches cannot start until both sides are populated.
- Match completion records a winner side (`A` / `B`) rather than trusting a frontend label.

### Competitive points
- Competitive points are separate from the Test Season wallet / prediction balance.
- Every completed match awards participation points and winner points through an immutable `season_point_entries` ledger.
- Current patch defaults: 10 participation points + 25 win points.
- Existing season wallet balances are not modified by competitive scoring.

### ELO
- Separate global player rating system starts at 1200.
- K-factor is 32.
- 1v1 results update winner and loser ratings server-side.
- Rating history is retained for later player profiles and ranking movement.
- 2v2 result support uses team-average ratings when a manual 2v2 match is completed.

### Admin UI
- Generate bracket button in Test Season match manager.
- Round-aware match display.
- Record-result flow asks for Side A or Side B.
- Competitive leaderboard shows ELO, points, W-L and peak rating.

## API additions
- `POST /api/admin/seasons/:seasonId/bracket`
- `GET /api/admin/seasons/:seasonId/leaderboard`
- `GET /api/leaderboard`
- Existing season match status endpoint now records competitive results atomically.

## Deliberately next
- Public ELO/Points leaderboard page.
- Clickable player profiles.
- Tournament-specific seasons/history and weekly/monthly/all-time leaderboard filters.
- More prediction types: percentage probability, round-reached, and exact-answer bonus markets.
- Tournament placement bonuses and season-end ranking finalization.

No DROP, TRUNCATE, database reset, or normal account-balance mutation was added.
