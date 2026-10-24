//! Invitations: a one-time link that lets a new administrator register the
//! first passkey. Only the hash of the token is stored.

use crate::db::Invite;
use crate::state::{hash_token, random_token, App};
use anyhow::Result;

pub fn create(
    app: &App,
    name: &str,
    email: &str,
    created_by: &str,
    hours: i64,
) -> Result<(String, Invite)> {
    let name = name.trim();
    let email = email.trim();
    anyhow::ensure!(
        !name.is_empty() && name.len() <= 80,
        "name: 1 to 80 characters"
    );
    anyhow::ensure!(
        email.contains('@') && email.len() <= 120 && !email.contains(char::is_whitespace),
        "e-mail: not valid"
    );
    let token = random_token();
    let invite = app
        .db
        .create_invite(&hash_token(&token), name, email, created_by, hours)?;
    let base = if app.cfg.base.is_empty() {
        "/".to_string()
    } else {
        format!("{}/", app.cfg.base)
    };
    let url = format!(
        "{}{}#invite={}",
        app.cfg.origin.as_str().trim_end_matches('/'),
        base,
        token
    );
    Ok((url, invite))
}
