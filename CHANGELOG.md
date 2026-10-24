# Changelog

## 0.1.0 — 2026-10-24

First release: buckets, keys and permissions over the Garage admin API v2;
passkey sign-in with one-time invitations; audit log; CLI (`serve`,
`invite`, `admins`, `disable`, `enable`, `check`).

## 0.1.1 — 2026-10-24

Fix: the navigation bar no longer shows on the invitation and sign-in pages.

## 0.1.2 — 2026-10-24

Build: OpenSSL vendored, so the Linux release binary is fully static.

## 0.2.0 — 2026-10-24

- Light theme on the Condepe/Fidem design system (navy bar, blue actions,
  Saira + JetBrains Mono embedded, zebra tables with hover).
- Keys: **Show secret** (audited as `key.secret_revealed`) and **Rotate**
  (new key, same name and permissions, old one deleted; audited as
  `key.rotated`). The "shown once" rule is dropped: the console still
  stores nothing, but an administrator can reveal a secret again.
- Fonts cached by the browser; everything else stays `no-store`.
- Icon buttons with app-styled tooltips in every table; styled selects; responsive form grids; counts and subtitles in page headers; name and id stacked in table cells.

## 0.2.1 — 2026-10-24

More breathing room between the navy bar and the page header.

## 0.3.0 — 2026-10-24

- **Overview** page (the new home): KPIs (buckets, objects and bytes, keys
  and how many can write, administrators and pending invitations,
  unfinished multipart uploads), alerts (keys without a bucket, buckets no
  key can reach, secret reveals in the last 7 days), largest buckets and
  recent activity.
- Faster: buckets and keys come from Garage's `ListBucketsInfo` /
  `ListKeysInfo` in one call each (fallback to one call per item on older
  Garage), and the UI keeps the last answer of each view, shows it at once
  and refreshes in the background; mutations clear the cache.
- Audit table: details rendered as key: value chips that wrap, dates and
  IPs kept on one line; no more overflow.
