---
'seamless-auth-api': patch
---

Index `auth_events` on `(user_id, created_at)`, `(type, created_at)` and `created_at`.

`auth_events` was indexed on `actor_user_id` and `session_id` but not on `user_id`, the
column the per-user event list filters by and the funnel queries self-join on, nor on
`type`, which the login stats and funnel queries filter by inside a `created_at` window,
nor on `created_at` itself, which every read orders or windows by. Each of those reads
scanned the whole table, which gains a row on every authentication and is never pruned.

`GET /admin/auth-events?userId=` now walks one index range in `created_at` order and
stops at the page limit instead of sorting every event for the user, and its paired
count is answered from the index alone. The same index serves the summary and
timeseries endpoints when scoped to a user. Login stats and the funnel queries' cohort
selection (`type = ... AND created_at BETWEEN ...`) read the `(type, created_at)` index,
and the time-to-login self-join uses it on both sides. The unfiltered event list, which
is the dashboard's default view, and the list windowed only by `from` and `to`, read
the newest page straight off the `created_at` index instead of sorting the whole table
for it. The migration only adds indexes and rolling back removes them.
