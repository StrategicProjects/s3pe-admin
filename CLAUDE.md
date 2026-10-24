# s3pe-admin — web console for Garage

Rust (axum 0.8, webauthn-rs 0.5, rusqlite, reqwest) + vanilla JS/CSS embedded
in the binary (`assets/`). Talks to Garage's admin API v2 on localhost with a
bearer token; passkeys-only sign-in; SQLite for admins, passkeys, invites,
sessions (hashed tokens) and audit. Deployed on the condepe server behind
nginx at https://s3.pe.gov.br/admin/ (condepefidem-platform ADR 0004).

Current: **0.3.1** (2026-10-24). Owner: André (leite@castlab.org); he talks
Portuguese, code and UI texts are in English.

## Working agreement

- Design: the Condepe/Fidem design system (`condepefidem-platform/packages/ui/tokens.css`):
  light theme, navy bar, blue actions, vibrant colours only as accents,
  Saira / Saira Condensed / JetBrains Mono (woff2 in `assets/fonts`, served by
  the binary; CSP allows no CDN). Zebra tables; icon buttons with CSS
  tooltips (`data-tip`, never `title`); styled selects; responsive form
  grids; page header = title + count + primary button + one-line lead.
  The user asks for these explicitly: keep them.
- Beware CSS specificity: `main` also carries `.wrap`; element selectors
  lose to class rules (that was the 0.3.1 bug).
- Security invariants: cookie `HttpOnly; Secure; SameSite=Strict; Path=/admin`;
  POST needs `Origin` == configured origin and `X-Requested-With: s3pe-admin`;
  CSP `script-src 'self'`; rate limit on `/login/*` and `/invite/*`; the
  console never stores key secrets (reveal and rotate are audited).
- Data loading: `/api/buckets` and `/api/keys` use Garage's `ListBucketsInfo`
  / `ListKeysInfo` (one call), with the N+1 path as fallback; the UI caches
  each GET per path (`cached()`), renders the last answer at once and
  refreshes in the background; any non-GET invalidates the cache.
- Bucket name `admin` is reserved (path collision with the console).

## Develop and test

- `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`
  (`tests/flow.rs` runs the whole flow over HTTP with a fake Garage and a
  `webauthn-authenticator-rs` SoftPasskey; the fake must mirror new Garage
  calls).
- Local Garage: `docker run -d --name s3pe-garage-local -p 127.0.0.1:9103:3900 -p 127.0.0.1:9113:3903 -v <garage.toml>:/etc/garage.toml:ro dxflrs/garage:v2.4.1 /garage server --single-node`
  with `[admin] api_bind_addr="[::]:3903"` and a test `admin_token`.
- Local console: `S3PE_ADMIN_DB=... GARAGE_ADMIN_URL=http://127.0.0.1:9113 GARAGE_ADMIN_TOKEN=... S3PE_ADMIN_ORIGIN=http://localhost:8097 cargo run -- serve`.
  To browse without a passkey: insert an admin and a session row in the
  SQLite DB (token hash = sha256 of a known string) and set
  `document.cookie = "s3pe_admin=<string>; path=/admin"` in Chrome.
- `node -e "new Function(require('fs').readFileSync('assets/app.js','utf8'))"` catches JS syntax errors.

## Release and deploy

1. Bump `Cargo.toml`, add a `CHANGELOG.md` entry, commit, `git tag vX.Y.Z`,
   push the tag: `release.yml` builds a static musl binary (OpenSSL vendored)
   and attaches `s3pe-admin-linux-x86_64` + `.sha256` to the GitHub release.
2. On the server (the user runs it; the permission classifier blocks this
   deploy from here and sudo needs a password):
   `bash ~/condepefidem-platform/current/scripts/deploy/instalar-s3-admin-remote.sh vX.Y.Z`
   then `sudo systemctl restart condepefidem-s3-admin`. The installer waits
   for the release asset: a 404 from curl means the release is still being
   published.
3. Invitations: UI (Administrators → Invite) or on the server
   `set -a; source ~/.condepefidem/s3-admin.env; set +a; ~/condepefidem-platform/shared/bin/s3pe-admin invite "Name" email`.
