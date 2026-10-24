//! Shared state: configuration, database, Garage client, WebAuthn, the
//! in-memory challenge store and the rate limiter.

use crate::db::Db;
use crate::garage::Garage;
use anyhow::{Context, Result};
use base64::Engine;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use webauthn_rs::prelude::*;

#[derive(Clone, Debug)]
pub struct Config {
    pub bind: String,
    pub db_path: std::path::PathBuf,
    pub origin: Url,
    pub base: String,
    pub rp_name: String,
    pub garage_url: String,
    pub garage_token: String,
    pub trust_proxy: bool,
    pub session_hours: i64,
}

impl Config {
    pub fn from_env() -> Result<Config> {
        let env = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
        let origin = env("S3PE_ADMIN_ORIGIN").unwrap_or_else(|| "http://localhost:8097".into());
        let origin = Url::parse(&origin).with_context(|| format!("S3PE_ADMIN_ORIGIN={origin}"))?;
        let token = match (env("GARAGE_ADMIN_TOKEN"), env("GARAGE_ADMIN_TOKEN_FILE")) {
            (Some(t), _) => t,
            (None, Some(f)) => std::fs::read_to_string(&f)
                .with_context(|| format!("reading {f}"))?
                .trim()
                .to_string(),
            (None, None) => anyhow::bail!("set GARAGE_ADMIN_TOKEN_FILE (or GARAGE_ADMIN_TOKEN)"),
        };
        let mut base = env("S3PE_ADMIN_BASE").unwrap_or_else(|| "/admin".into());
        if !base.starts_with('/') {
            base.insert(0, '/');
        }
        let base = base.trim_end_matches('/').to_string();
        Ok(Config {
            bind: env("S3PE_ADMIN_BIND").unwrap_or_else(|| "127.0.0.1:8097".into()),
            db_path: env("S3PE_ADMIN_DB")
                .unwrap_or_else(|| "s3pe-admin.db".into())
                .into(),
            origin,
            base,
            rp_name: env("S3PE_ADMIN_RP_NAME").unwrap_or_else(|| "s3pe admin".into()),
            garage_url: env("GARAGE_ADMIN_URL").unwrap_or_else(|| "http://127.0.0.1:3903".into()),
            garage_token: token,
            trust_proxy: env("S3PE_ADMIN_TRUST_PROXY")
                .map(|v| v != "0")
                .unwrap_or(false),
            session_hours: env("S3PE_ADMIN_SESSION_HOURS")
                .and_then(|v| v.parse().ok())
                .unwrap_or(12),
        })
    }
}

/// A pending WebAuthn ceremony, kept in memory for a few minutes.
pub enum Pending {
    Invite {
        invite_id: i64,
        name: String,
        email: String,
        state: PasskeyRegistration,
    },
    AddPasskey {
        admin_id: String,
        state: PasskeyRegistration,
    },
    Login {
        admin_id: String,
        state: PasskeyAuthentication,
    },
}

pub struct AppState {
    pub cfg: Config,
    pub db: Db,
    pub garage: Garage,
    pub webauthn: Webauthn,
    pending: Mutex<HashMap<String, (Instant, Pending)>>,
    attempts: Mutex<HashMap<String, (Instant, u32)>>,
}

pub type App = Arc<AppState>;

pub const PENDING_TTL: Duration = Duration::from_secs(300);
pub const AUTH_ATTEMPTS: u32 = 20;
pub const AUTH_WINDOW: Duration = Duration::from_secs(600);

impl AppState {
    pub fn new(cfg: Config, db: Db) -> Result<App> {
        let rp_id = cfg
            .origin
            .host_str()
            .context("origin without host")?
            .to_string();
        let webauthn = WebauthnBuilder::new(&rp_id, &cfg.origin)?
            .rp_name(&cfg.rp_name)
            .timeout(Duration::from_secs(120))
            .build()?;
        let garage = Garage::new(&cfg.garage_url, &cfg.garage_token);
        Ok(Arc::new(AppState {
            cfg,
            db,
            garage,
            webauthn,
            pending: Mutex::new(HashMap::new()),
            attempts: Mutex::new(HashMap::new()),
        }))
    }

    pub fn put_pending(&self, p: Pending) -> String {
        let id = random_token();
        let mut map = self.pending.lock().unwrap();
        map.retain(|_, (t, _)| t.elapsed() < PENDING_TTL);
        map.insert(id.clone(), (Instant::now(), p));
        id
    }

    pub fn take_pending(&self, id: &str) -> Option<Pending> {
        let mut map = self.pending.lock().unwrap();
        map.remove(id)
            .filter(|(t, _)| t.elapsed() < PENDING_TTL)
            .map(|(_, p)| p)
    }

    /// Counts an authentication attempt from `ip`; `false` when over the limit.
    pub fn allow_attempt(&self, ip: &str) -> bool {
        let mut map = self.attempts.lock().unwrap();
        map.retain(|_, (t, _)| t.elapsed() < AUTH_WINDOW);
        let entry = map.entry(ip.to_string()).or_insert((Instant::now(), 0));
        entry.1 += 1;
        entry.1 <= AUTH_ATTEMPTS
    }
}

/// 32 random bytes, base64url without padding.
pub fn random_token() -> String {
    use rand::RngCore;
    let mut b = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut b);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

/// Hex SHA-256, what the database stores instead of tokens.
pub fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}
