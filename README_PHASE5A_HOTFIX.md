# Ossper v2.3.1 — Phase 5A Live Roster Hotfix

This patch is designed for testing Ossper against a real tournament **without asking every player to create an Ossper account or manually enrolling them one by one**.

## Quick roster import

In **Admin → Test Season → Players**, use **Quick roster import**.

Paste one player per line:

```text
Player One
Player Two
Player Three
```

Optional format when Discord IDs are available:

```text
Player One | 123456789012345678
Player Two | 987654321098765432
```

The importer creates test-only Ossper identities and enrolls them in the selected Test Season. Normal account balances are not changed.

## Non-power-of-two brackets

Automatic 1v1 brackets now accept any field from **2 through 32 players**.

For a 10-player field, Ossper pads the bracket to 16 slots and creates automatic **BYEs**. BYE advances do not award points or ELO and are recorded as system events, so the first real match can be tested without forcing fake players into the bracket.

## Safety

- Test roster identities use `auth_provider='test'`.
- Generated roster accounts do not receive Discord authentication sessions.
- Existing normal balances are untouched.
- Roster import is blocked after the season has started.
- Bracket generation remains blocked once matches already exist.
- All imports and bracket generation are written to the audit log.
