# s3pe-admin

[![CI](https://github.com/StrategicProjects/s3pe-admin/actions/workflows/ci.yml/badge.svg)](https://github.com/StrategicProjects/s3pe-admin/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A small, secure web console for a [Garage](https://garagehq.deuxfleurs.fr)
object store: buckets, access keys and permissions, with passkey sign-in and
an audit log. One static binary, no runtime dependencies, listening on
localhost behind your reverse proxy. The companion of
[s3pe](https://github.com/StrategicProjects/s3pe).

## What it does

- **Buckets**: list with objects, size and the keys that can reach them;
  create (S3 naming rules enforced, a few names reserved); delete only when
  empty, after typing the name.
- **Keys**: create a key for a bucket with a profile, *read only* or *read
  and write*; create a bucket with its two keys (`name` and `name-leitura`)
  in one step; give or remove a key's access to a bucket; delete after
  typing the name. The secret is shown **once**, at creation, with a "copy
  as `.Renviron`/`.env` lines" button; the console never stores it and
  never shows it again.
- **Administrators**: invitation links (one use, 24 h), passkeys per
  administrator (add, remove, never the last one), disable/enable.
- **Audit**: who did what, when, from which IP; exportable as JSON.

What it does not do, on purpose: browse objects, ACLs, bucket policies,
website access, quotas (planned), cluster layout.

## Security model

- Sign-in with **passkeys only** (WebAuthn): Touch ID, Windows Hello,
  security keys. No passwords anywhere.
- Session cookie `HttpOnly; Secure; SameSite=Strict`, scoped to the console
  path, 12 h; the database stores only SHA-256 hashes of session and
  invitation tokens.
- Every state-changing request must carry `X-Requested-With: s3pe-admin`
  and an `Origin` equal to the configured origin.
- Strict `Content-Security-Policy` (`script-src 'self'`, no inline, no CDN),
  `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cache-Control:
  no-store`, HSTS.
- Authentication endpoints are rate limited per IP (20 attempts per 10 min).
- The console talks to Garage's admin API on localhost with a bearer token
  read from a file; it listens on `127.0.0.1` only.
- Logged-in administrators are peers: everyone sees everything, every
  action is audited.

## Run

```bash
export S3PE_ADMIN_ORIGIN=https://s3.example.org      # what the browser sees
export S3PE_ADMIN_BASE=/admin                        # path under the origin
export S3PE_ADMIN_BIND=127.0.0.1:8097
export S3PE_ADMIN_DB=/var/lib/s3pe-admin/admin.db
export S3PE_ADMIN_TRUST_PROXY=1                      # take the IP from X-Forwarded-For
export GARAGE_ADMIN_URL=http://127.0.0.1:3903
export GARAGE_ADMIN_TOKEN_FILE=/etc/s3pe-admin/garage-admin-token

s3pe-admin check                                     # reaches Garage?
s3pe-admin invite "Ana" ana@example.org              # prints a one-time link
s3pe-admin serve
```

Garage needs the admin API on (`[admin] api_bind_addr`, `admin_token` or
`GARAGE_ADMIN_TOKEN`). nginx forwards the console path and passes the
client IP:

```nginx
location /admin/ {
    proxy_pass http://127.0.0.1:8097/admin/;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

Other commands: `admins`, `disable <email>`, `enable <email>`.

## Develop

```bash
cargo test            # unit tests + an end-to-end flow with a fake Garage and a software passkey
cargo run -- check    # against a local Garage (docker run dxflrs/garage with [admin] configured)
```

## Made in Pernambuco 🌵

MIT. By the authors of s3pe.
