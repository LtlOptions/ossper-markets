# Ossper Markets — Phase 6 Double-Elimination Tournament Engine

## What changed
- Replaced the Test Season automatic single-elimination 1v1 bracket with a standard double-elimination structure.
- Winners advance through the Winners Bracket.
- A first loss drops the player into the appropriate Losers Bracket round.
- A second competitive loss eliminates the player.
- Grand Final #1 pits the Winners Bracket champion against the Losers Bracket champion.
- If the Losers Bracket champion wins Grand Final #1, a Grand Final Reset is activated automatically.
- BYEs do not count as competitive matches and do not change ELO or points.
- Admin bracket view is grouped into Winners Bracket, Losers Bracket, and Grand Final with directional arrows and routing labels.
- Admin elimination breakdown lists players as soon as they receive their second loss and identifies the champion when the final is complete.

## Repeatable testing
Restart Tournament still preserves the roster while clearing the current competitive run. The next run creates a fresh double-elimination bracket and restores the ELO snapshot captured at the beginning of the prior run.
