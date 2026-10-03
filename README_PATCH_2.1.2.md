# Ossper Markets v2.1.2 — Date & Time Zone Fix

Focused date/time-only patch on top of v2.1.1.

- Fixes Test Season match creation so `scheduled_at` is stored correctly.
- Recovers legacy season-match scheduled times from TEST_SEASON_MATCH_CREATED audit entries when `scheduled_at` is still null.
- Recovers legacy main tournament scheduled times from CREATE_MATCH_MARKET audit entries when `matches.scheduled_at` is still null.
- Season/public match APIs tolerate legacy SCHEDULED rows by falling back to `started_at` only when the match has never started.
- Frontend dates/times default to each viewer's device timezone.
- Adds an optional Settings override for common time zones and UTC.
- Admin date display now explicitly includes the browser's timezone abbreviation.

No destructive SQL. No account balance changes. No season deletion.
