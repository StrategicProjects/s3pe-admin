//! SQLite storage: administrators, passkeys, invites, sessions, audit log.

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct Db(Arc<Mutex<Connection>>);

#[derive(Debug, Clone, serde::Serialize)]
pub struct Admin {
    pub id: String,
    pub name: String,
    pub email: String,
    pub created_at: String,
    pub disabled: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PasskeyRow {
    pub id: i64,
    pub admin_id: String,
    pub name: String,
    #[serde(skip)]
    pub passkey_json: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Invite {
    pub id: i64,
    pub name: String,
    pub email: String,
    pub created_by: String,
    pub created_at: String,
    pub expires_at: String,
    pub used_at: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditEntry {
    pub id: i64,
    pub ts: String,
    pub admin: String,
    pub action: String,
    pub target: String,
    pub details: serde_json::Value,
    pub ip: String,
}

pub fn now() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

pub fn in_secs(secs: i64) -> String {
    (time::OffsetDateTime::now_utc() + time::Duration::seconds(secs))
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

impl Db {
    pub fn open(path: &Path) -> Result<Db> {
        let conn = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA foreign_keys = ON;
             PRAGMA busy_timeout = 5000;
             CREATE TABLE IF NOT EXISTS admins (
               id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE COLLATE NOCASE,
               created_at TEXT NOT NULL, disabled INTEGER NOT NULL DEFAULT 0);
             CREATE TABLE IF NOT EXISTS passkeys (
               id INTEGER PRIMARY KEY, admin_id TEXT NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
               name TEXT NOT NULL, cred_id BLOB NOT NULL UNIQUE, passkey_json TEXT NOT NULL,
               created_at TEXT NOT NULL, last_used_at TEXT);
             CREATE TABLE IF NOT EXISTS invites (
               id INTEGER PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
               email TEXT NOT NULL, created_by TEXT NOT NULL, created_at TEXT NOT NULL,
               expires_at TEXT NOT NULL, used_at TEXT);
             CREATE TABLE IF NOT EXISTS sessions (
               token_hash TEXT PRIMARY KEY, admin_id TEXT NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
               created_at TEXT NOT NULL, expires_at TEXT NOT NULL, ip TEXT NOT NULL, user_agent TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS audit (
               id INTEGER PRIMARY KEY, ts TEXT NOT NULL, admin TEXT NOT NULL, action TEXT NOT NULL,
               target TEXT NOT NULL, details TEXT NOT NULL, ip TEXT NOT NULL);
             CREATE INDEX IF NOT EXISTS audit_ts ON audit(ts);",
        )?;
        Ok(Db(Arc::new(Mutex::new(conn))))
    }

    fn with<T>(&self, f: impl FnOnce(&Connection) -> rusqlite::Result<T>) -> Result<T> {
        let conn = self.0.lock().unwrap();
        Ok(f(&conn)?)
    }

    // ---- admins

    pub fn admins(&self) -> Result<Vec<Admin>> {
        self.with(|c| {
            let mut st = c.prepare(
                "SELECT id, name, email, created_at, disabled FROM admins ORDER BY created_at",
            )?;
            let rows = st.query_map([], |r| {
                Ok(Admin {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    email: r.get(2)?,
                    created_at: r.get(3)?,
                    disabled: r.get::<_, i64>(4)? != 0,
                })
            })?;
            rows.collect()
        })
    }

    pub fn admin_by_email(&self, email: &str) -> Result<Option<Admin>> {
        self.with(|c| {
            c.query_row(
                "SELECT id, name, email, created_at, disabled FROM admins WHERE email = ?1",
                params![email.trim()],
                |r| {
                    Ok(Admin {
                        id: r.get(0)?,
                        name: r.get(1)?,
                        email: r.get(2)?,
                        created_at: r.get(3)?,
                        disabled: r.get::<_, i64>(4)? != 0,
                    })
                },
            )
            .optional()
        })
    }

    pub fn admin_by_id(&self, id: &str) -> Result<Option<Admin>> {
        self.with(|c| {
            c.query_row(
                "SELECT id, name, email, created_at, disabled FROM admins WHERE id = ?1",
                params![id],
                |r| {
                    Ok(Admin {
                        id: r.get(0)?,
                        name: r.get(1)?,
                        email: r.get(2)?,
                        created_at: r.get(3)?,
                        disabled: r.get::<_, i64>(4)? != 0,
                    })
                },
            )
            .optional()
        })
    }

    pub fn create_admin(&self, name: &str, email: &str) -> Result<Admin> {
        let id = uuid::Uuid::new_v4().to_string();
        let created = now();
        self.with(|c| {
            c.execute(
                "INSERT INTO admins (id, name, email, created_at, disabled) VALUES (?1, ?2, ?3, ?4, 0)",
                params![id, name.trim(), email.trim(), created],
            )
        })?;
        Ok(Admin {
            id,
            name: name.trim().into(),
            email: email.trim().into(),
            created_at: created,
            disabled: false,
        })
    }

    pub fn set_admin_disabled(&self, id: &str, disabled: bool) -> Result<bool> {
        let n = self.with(|c| {
            c.execute(
                "UPDATE admins SET disabled = ?2 WHERE id = ?1",
                params![id, disabled as i64],
            )
        })?;
        if disabled {
            self.with(|c| c.execute("DELETE FROM sessions WHERE admin_id = ?1", params![id]))?;
        }
        Ok(n > 0)
    }

    // ---- passkeys

    pub fn passkeys_of(&self, admin_id: &str) -> Result<Vec<PasskeyRow>> {
        self.with(|c| {
            let mut st = c.prepare("SELECT id, admin_id, name, passkey_json, created_at, last_used_at FROM passkeys WHERE admin_id = ?1 ORDER BY created_at")?;
            let rows = st.query_map(params![admin_id], |r| {
                Ok(PasskeyRow { id: r.get(0)?, admin_id: r.get(1)?, name: r.get(2)?, passkey_json: r.get(3)?, created_at: r.get(4)?, last_used_at: r.get(5)? })
            })?;
            rows.collect()
        })
    }

    pub fn add_passkey(
        &self,
        admin_id: &str,
        name: &str,
        cred_id: &[u8],
        passkey_json: &str,
    ) -> Result<i64> {
        self.with(|c| {
            c.execute(
                "INSERT INTO passkeys (admin_id, name, cred_id, passkey_json, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![admin_id, name.trim(), cred_id, passkey_json, now()],
            )?;
            Ok(c.last_insert_rowid())
        })
    }

    pub fn update_passkey(&self, id: i64, passkey_json: &str) -> Result<()> {
        self.with(|c| {
            c.execute(
                "UPDATE passkeys SET passkey_json = ?2, last_used_at = ?3 WHERE id = ?1",
                params![id, passkey_json, now()],
            )
        })?;
        Ok(())
    }

    pub fn delete_passkey(&self, admin_id: &str, id: i64) -> Result<bool> {
        let n = self.with(|c| {
            c.execute(
                "DELETE FROM passkeys WHERE id = ?1 AND admin_id = ?2",
                params![id, admin_id],
            )
        })?;
        Ok(n > 0)
    }

    // ---- invites

    pub fn create_invite(
        &self,
        token_hash: &str,
        name: &str,
        email: &str,
        created_by: &str,
        hours: i64,
    ) -> Result<Invite> {
        let created = now();
        let expires = in_secs(hours * 3600);
        let id = self.with(|c| {
            c.execute(
                "INSERT INTO invites (token_hash, name, email, created_by, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![token_hash, name.trim(), email.trim(), created_by, created, expires],
            )?;
            Ok(c.last_insert_rowid())
        })?;
        Ok(Invite {
            id,
            name: name.trim().into(),
            email: email.trim().into(),
            created_by: created_by.into(),
            created_at: created,
            expires_at: expires,
            used_at: None,
        })
    }

    /// A pending (unused, unexpired) invite for this token hash.
    pub fn invite_by_hash(&self, token_hash: &str) -> Result<Option<Invite>> {
        let inv: Option<Invite> = self.with(|c| {
            c.query_row(
                "SELECT id, name, email, created_by, created_at, expires_at, used_at FROM invites WHERE token_hash = ?1",
                params![token_hash],
                |r| Ok(Invite { id: r.get(0)?, name: r.get(1)?, email: r.get(2)?, created_by: r.get(3)?, created_at: r.get(4)?, expires_at: r.get(5)?, used_at: r.get(6)? }),
            )
            .optional()
        })?;
        Ok(inv.filter(|i| i.used_at.is_none() && i.expires_at > now()))
    }

    /// The invite with this id if it is still pending (unused, unexpired).
    pub fn invite_pending(&self, id: i64) -> Result<Option<Invite>> {
        let inv: Option<Invite> = self.with(|c| {
            c.query_row(
                "SELECT id, name, email, created_by, created_at, expires_at, used_at FROM invites WHERE id = ?1",
                params![id],
                |r| Ok(Invite { id: r.get(0)?, name: r.get(1)?, email: r.get(2)?, created_by: r.get(3)?, created_at: r.get(4)?, expires_at: r.get(5)?, used_at: r.get(6)? }),
            )
            .optional()
        })?;
        Ok(inv.filter(|i| i.used_at.is_none() && i.expires_at > now()))
    }

    pub fn use_invite(&self, id: i64) -> Result<()> {
        self.with(|c| {
            c.execute(
                "UPDATE invites SET used_at = ?2 WHERE id = ?1",
                params![id, now()],
            )
        })?;
        Ok(())
    }

    pub fn invites(&self) -> Result<Vec<Invite>> {
        self.with(|c| {
            let mut st = c.prepare("SELECT id, name, email, created_by, created_at, expires_at, used_at FROM invites ORDER BY created_at DESC LIMIT 50")?;
            let rows = st.query_map([], |r| Ok(Invite { id: r.get(0)?, name: r.get(1)?, email: r.get(2)?, created_by: r.get(3)?, created_at: r.get(4)?, expires_at: r.get(5)?, used_at: r.get(6)? }))?;
            rows.collect()
        })
    }

    // ---- sessions

    pub fn create_session(
        &self,
        token_hash: &str,
        admin_id: &str,
        secs: i64,
        ip: &str,
        user_agent: &str,
    ) -> Result<()> {
        self.with(|c| {
            c.execute(
                "INSERT INTO sessions (token_hash, admin_id, created_at, expires_at, ip, user_agent) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![token_hash, admin_id, now(), in_secs(secs), ip, user_agent],
            )
        })?;
        Ok(())
    }

    /// The admin of a live session, or `None`.
    pub fn session_admin(&self, token_hash: &str) -> Result<Option<Admin>> {
        self.with(|c| {
            c.query_row(
                "SELECT a.id, a.name, a.email, a.created_at, a.disabled FROM sessions s JOIN admins a ON a.id = s.admin_id
                 WHERE s.token_hash = ?1 AND s.expires_at > ?2 AND a.disabled = 0",
                params![token_hash, now()],
                |r| Ok(Admin { id: r.get(0)?, name: r.get(1)?, email: r.get(2)?, created_at: r.get(3)?, disabled: r.get::<_, i64>(4)? != 0 }),
            )
            .optional()
        })
    }

    pub fn delete_session(&self, token_hash: &str) -> Result<()> {
        self.with(|c| {
            c.execute(
                "DELETE FROM sessions WHERE token_hash = ?1",
                params![token_hash],
            )
        })?;
        Ok(())
    }

    pub fn purge_expired(&self) -> Result<()> {
        self.with(|c| {
            c.execute(
                "DELETE FROM sessions WHERE expires_at <= ?1",
                params![now()],
            )
        })?;
        Ok(())
    }

    // ---- audit

    pub fn audit(
        &self,
        admin: &str,
        action: &str,
        target: &str,
        details: serde_json::Value,
        ip: &str,
    ) -> Result<()> {
        self.with(|c| {
            c.execute(
                "INSERT INTO audit (ts, admin, action, target, details, ip) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![now(), admin, action, target, details.to_string(), ip],
            )
        })?;
        Ok(())
    }

    pub fn audit_entries(&self, limit: i64) -> Result<Vec<AuditEntry>> {
        self.with(|c| {
            let mut st = c.prepare("SELECT id, ts, admin, action, target, details, ip FROM audit ORDER BY id DESC LIMIT ?1")?;
            let rows = st.query_map(params![limit.clamp(1, 5000)], |r| {
                let details: String = r.get(5)?;
                Ok(AuditEntry {
                    id: r.get(0)?, ts: r.get(1)?, admin: r.get(2)?, action: r.get(3)?, target: r.get(4)?,
                    details: serde_json::from_str(&details).unwrap_or(serde_json::Value::Null), ip: r.get(6)?,
                })
            })?;
            rows.collect()
        })
    }
}
