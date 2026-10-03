# Ossper Markets v2.0.3 — UI + Season Match Hotfix

This patch is built from the v2.0.2 Phase 3 source package and is additive/non-destructive.

## Changes
- Fixed Test Season scheduled match time handling:
  - browser local datetime is normalized to an ISO timestamp before submission
  - invalid entered times are rejected instead of silently becoming `No time set`
  - admin confirmation reports the saved schedule
  - server validates and normalizes the stored timestamp
- Preserved custom Side A / Side B labels throughout season match rendering.
- Refined the Test Season simulation indicator so it reads as an intentional platform environment marker rather than a warning.
- Reworked the notification bell into a cleaner Ossper-style control.
- Notification panel now follows the same hover/tap interaction model as Settings:
  - desktop hover
  - mobile tap
  - closes when clicking elsewhere
  - remains inside the viewport on mobile
- No database reset, DROP, TRUNCATE, or destructive migration was added.

## Deployment
Replace the existing application source with this package and deploy normally. Existing PostgreSQL data is retained.
