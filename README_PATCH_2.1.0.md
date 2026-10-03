Ossper Markets v2.1.0 — Polish / Accuracy Pack

Base: v2.0.2 public Test Season build.

Included:
- Test Season user-facing date metadata with local-time formatting and fallbacks.
- Simulation header badge refinement.
- Notification popover anchored to the bell; desktop hover behavior with mobile click behavior and outside-click closing.
- Higher-contrast glass account menu.
- Demo-market identification/motion and admin lifecycle controls.
- Cleaner wager cancel button.
- Activity filters + pagination.
- Market chart timeframe controls, plot-area crosshair alignment, and adaptive tooltip positioning.
- Portfolio chart uses trade-linked ledger balance_after data and appends current marked equity.
- Admin match groups expose empty states; themed admin inputs/selects/textarea replace generic blue controls.
- Season match scheduled_at is now actually written during creation.
- Existing Test Season/public/match functionality preserved.

Safety:
- No DROP TABLE/TRUNCATE/DROP DATABASE operations.
- No account balance reset.
- No destructive data migration.
