//! HTTP routes: static assets, authentication (passkeys), the console API.

use crate::db::Admin;
use crate::garage::{valid_bucket_name, valid_key_name, Perm};
use crate::state::{hash_token, random_token, App, Pending};
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use std::net::SocketAddr;
use webauthn_rs::prelude::*;

const COOKIE: &str = "s3pe_admin";
const INDEX: &str = include_str!("../assets/index.html");
const APP_JS: &str = include_str!("../assets/app.js");
const STYLE: &str = include_str!("../assets/style.css");

/// A JSON error with a status.
pub struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        tracing::warn!("{e:#}");
        ApiError(StatusCode::BAD_GATEWAY, e.to_string())
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(e: serde_json::Error) -> Self {
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, format!("json: {e}"))
    }
}

fn bad(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, msg.into())
}
fn unauthorized() -> ApiError {
    ApiError(StatusCode::UNAUTHORIZED, "sign in first".into())
}
fn too_many() -> ApiError {
    ApiError(
        StatusCode::TOO_MANY_REQUESTS,
        "too many attempts; wait a few minutes".into(),
    )
}

type ApiResult = Result<Json<Value>, ApiError>;

/// The signed-in administrator, put in request extensions by the middleware.
#[derive(Clone)]
pub struct Session {
    pub admin: Admin,
    pub token_hash: String,
}

/// Request context the handlers need: IP and user agent.
#[derive(Clone)]
pub struct Ctx {
    pub ip: String,
    pub user_agent: String,
}

pub fn router(app: App) -> Router {
    let base = app.cfg.base.clone();
    let api = Router::new()
        .route("/me", get(me))
        .route("/health", get(health))
        .route("/login/begin", post(login_begin))
        .route("/login/finish", post(login_finish))
        .route("/invite/begin", post(invite_begin))
        .route("/invite/finish", post(invite_finish))
        .route("/logout", post(logout))
        .route("/buckets", get(buckets).post(create_bucket))
        .route("/buckets/{id}", get(bucket))
        .route("/buckets/{id}/delete", post(delete_bucket))
        .route("/buckets/{id}/allow", post(allow_key))
        .route("/buckets/{id}/deny", post(deny_key))
        .route("/keys", get(keys).post(create_key))
        .route("/keys/{id}", get(key))
        .route("/keys/{id}/delete", post(delete_key))
        .route("/audit", get(audit))
        .route("/admins", get(admins))
        .route("/admins/invite", post(admin_invite))
        .route("/admins/{id}/disable", post(admin_disable))
        .route("/admins/{id}/enable", post(admin_enable))
        .route("/passkeys", get(passkeys))
        .route("/passkeys/begin", post(passkey_begin))
        .route("/passkeys/finish", post(passkey_finish))
        .route("/passkeys/{id}/delete", post(passkey_delete))
        .layer(middleware::from_fn_with_state(app.clone(), authenticate));
    // Explicit paths rather than `nest`: `/admin` and `/admin/` both serve the page.
    let mut router = Router::new()
        .route(&format!("{base}/"), get(index))
        .route(&format!("{base}/app.js"), get(app_js))
        .route(&format!("{base}/style.css"), get(style))
        .nest(&format!("{base}/api"), api);
    if !base.is_empty() {
        router = router
            .route(&base, get(redirect_to_base))
            .route("/", get(redirect_to_base));
    }
    router
        .layer(middleware::from_fn(security_headers))
        .with_state(app)
}

// ---------------------------------------------------------------- middleware

async fn security_headers(req: axum::extract::Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"),
    );
    h.insert(
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=31536000"),
    );
    h.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    resp
}

/// Resolves the session cookie into a `Session` extension, computes `Ctx`,
/// and blocks cross-site state changes (origin + custom header).
async fn authenticate(
    State(app): State<App>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    mut req: axum::extract::Request,
    next: Next,
) -> Response {
    let headers = req.headers().clone();
    let ip = client_ip(&app, &headers, addr);
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .chars()
        .take(200)
        .collect();
    req.extensions_mut().insert(Ctx { ip, user_agent: ua });

    if req.method() != Method::GET && req.method() != Method::HEAD {
        let origin_ok = headers
            .get(header::ORIGIN)
            .and_then(|v| v.to_str().ok())
            .map(|o| o.trim_end_matches('/') == app.cfg.origin.as_str().trim_end_matches('/'))
            .unwrap_or(false);
        let marker_ok = headers
            .get("x-requested-with")
            .map(|v| v == "s3pe-admin")
            .unwrap_or(false);
        if !origin_ok || !marker_ok {
            return ApiError(StatusCode::FORBIDDEN, "cross-site request refused".into())
                .into_response();
        }
    }

    if let Some(token) = cookie(&headers, COOKIE) {
        let hash = hash_token(&token);
        if let Ok(Some(admin)) = app.db.session_admin(&hash) {
            req.extensions_mut().insert(Session {
                admin,
                token_hash: hash,
            });
        }
    }
    next.run(req).await
}

fn client_ip(app: &App, headers: &HeaderMap, addr: SocketAddr) -> String {
    if app.cfg.trust_proxy {
        if let Some(v) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            if let Some(first) = v.split(',').next().map(str::trim).filter(|s| !s.is_empty()) {
                return first.to_string();
            }
        }
    }
    addr.ip().to_string()
}

fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .map(str::trim)
        .find_map(|kv| {
            kv.strip_prefix(name)
                .and_then(|rest| rest.strip_prefix('='))
                .map(str::to_string)
        })
}

fn set_cookie(app: &App, token: Option<&str>) -> HeaderValue {
    let path = if app.cfg.base.is_empty() {
        "/"
    } else {
        app.cfg.base.as_str()
    };
    let secure = if app.cfg.origin.scheme() == "https" {
        "; Secure"
    } else {
        ""
    };
    let v = match token {
        Some(t) => format!(
            "{COOKIE}={t}; Path={path}; HttpOnly; SameSite=Strict{secure}; Max-Age={}",
            app.cfg.session_hours * 3600
        ),
        None => format!("{COOKIE}=; Path={path}; HttpOnly; SameSite=Strict{secure}; Max-Age=0"),
    };
    HeaderValue::from_str(&v).unwrap()
}

fn session(req_ext: &axum::http::Extensions) -> Result<Session, ApiError> {
    req_ext.get::<Session>().cloned().ok_or_else(unauthorized)
}

fn ctx(req_ext: &axum::http::Extensions) -> Ctx {
    req_ext.get::<Ctx>().cloned().unwrap_or(Ctx {
        ip: "?".into(),
        user_agent: String::new(),
    })
}

async fn start_session(app: &App, admin: &Admin, c: &Ctx) -> Result<HeaderValue, ApiError> {
    let token = random_token();
    app.db.create_session(
        &hash_token(&token),
        &admin.id,
        app.cfg.session_hours * 3600,
        &c.ip,
        &c.user_agent,
    )?;
    app.db
        .audit(&admin.email, "login", &admin.email, json!({}), &c.ip)?;
    Ok(set_cookie(app, Some(&token)))
}

// ---------------------------------------------------------------- pages

async fn index(State(app): State<App>) -> Response {
    let html = INDEX.replace("{{BASE}}", &app.cfg.base);
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], html).into_response()
}

async fn app_js() -> Response {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        APP_JS,
    )
        .into_response()
}

async fn style() -> Response {
    ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], STYLE).into_response()
}

async fn redirect_to_base(State(app): State<App>) -> Response {
    axum::response::Redirect::to(&format!("{}/", app.cfg.base)).into_response()
}

// ---------------------------------------------------------------- auth

#[derive(Deserialize)]
struct LoginBegin {
    email: String,
}

async fn login_begin(
    State(app): State<App>,
    ext: axum::http::Extensions,
    Json(body): Json<LoginBegin>,
) -> ApiResult {
    let c = ctx(&ext);
    if !app.allow_attempt(&c.ip) {
        return Err(too_many());
    }
    let admin = app.db.admin_by_email(&body.email)?.filter(|a| !a.disabled);
    let Some(admin) = admin else {
        // Same answer as "no passkeys": the form shows a generic message.
        return Err(ApiError(
            StatusCode::UNAUTHORIZED,
            "no passkey registered for this e-mail".into(),
        ));
    };
    let rows = app.db.passkeys_of(&admin.id)?;
    let keys: Vec<Passkey> = rows
        .iter()
        .filter_map(|r| serde_json::from_str(&r.passkey_json).ok())
        .collect();
    if keys.is_empty() {
        return Err(ApiError(
            StatusCode::UNAUTHORIZED,
            "no passkey registered for this e-mail".into(),
        ));
    }
    let (rcr, state) = app
        .webauthn
        .start_passkey_authentication(&keys)
        .map_err(|e| bad(e.to_string()))?;
    let id = app.put_pending(Pending::Login {
        admin_id: admin.id,
        state,
    });
    Ok(Json(json!({ "challenge_id": id, "options": rcr })))
}

#[derive(Deserialize)]
struct Finish {
    challenge_id: String,
    credential: Value,
    #[serde(default)]
    passkey_name: String,
}

async fn login_finish(
    State(app): State<App>,
    ext: axum::http::Extensions,
    Json(body): Json<Finish>,
) -> Result<Response, ApiError> {
    let c = ctx(&ext);
    if !app.allow_attempt(&c.ip) {
        return Err(too_many());
    }
    let Some(Pending::Login { admin_id, state }) = app.take_pending(&body.challenge_id) else {
        return Err(bad("the sign-in challenge expired; try again"));
    };
    let cred: PublicKeyCredential =
        serde_json::from_value(body.credential).map_err(|e| bad(format!("bad credential: {e}")))?;
    let result = app
        .webauthn
        .finish_passkey_authentication(&cred, &state)
        .map_err(|e| {
            tracing::warn!("passkey authentication failed from {}: {e}", c.ip);
            ApiError(
                StatusCode::UNAUTHORIZED,
                "the passkey was not accepted".into(),
            )
        })?;
    let admin = app
        .db
        .admin_by_id(&admin_id)?
        .filter(|a| !a.disabled)
        .ok_or_else(unauthorized)?;
    // Update the stored passkey (counter) when the library asks for it.
    for row in app.db.passkeys_of(&admin.id)? {
        if let Ok(mut pk) = serde_json::from_str::<Passkey>(&row.passkey_json) {
            if pk.cred_id() == result.cred_id() {
                pk.update_credential(&result);
                app.db
                    .update_passkey(row.id, &serde_json::to_string(&pk)?)?;
            }
        }
    }
    let cookie = start_session(&app, &admin, &c).await?;
    Ok((
        [(header::SET_COOKIE, cookie)],
        Json(json!({ "ok": true, "admin": admin })),
    )
        .into_response())
}

#[derive(Deserialize)]
struct InviteBegin {
    token: String,
}

async fn invite_begin(
    State(app): State<App>,
    ext: axum::http::Extensions,
    Json(body): Json<InviteBegin>,
) -> ApiResult {
    let c = ctx(&ext);
    if !app.allow_attempt(&c.ip) {
        return Err(too_many());
    }
    let invite = app
        .db
        .invite_by_hash(&hash_token(body.token.trim()))?
        .ok_or_else(|| bad("this invitation is not valid any more"))?;
    let (ccr, state) = app
        .webauthn
        .start_passkey_registration(Uuid::new_v4(), &invite.email, &invite.name, None)
        .map_err(|e| bad(e.to_string()))?;
    let id = app.put_pending(Pending::Invite {
        invite_id: invite.id,
        name: invite.name.clone(),
        email: invite.email.clone(),
        state,
    });
    Ok(Json(
        json!({ "challenge_id": id, "options": ccr, "name": invite.name, "email": invite.email }),
    ))
}

async fn invite_finish(
    State(app): State<App>,
    ext: axum::http::Extensions,
    Json(body): Json<Finish>,
) -> Result<Response, ApiError> {
    let c = ctx(&ext);
    if !app.allow_attempt(&c.ip) {
        return Err(too_many());
    }
    let Some(Pending::Invite {
        invite_id,
        name,
        email,
        state,
    }) = app.take_pending(&body.challenge_id)
    else {
        return Err(bad(
            "the registration challenge expired; open the invitation again",
        ));
    };
    let cred: RegisterPublicKeyCredential =
        serde_json::from_value(body.credential).map_err(|e| bad(format!("bad credential: {e}")))?;
    let passkey = app
        .webauthn
        .finish_passkey_registration(&cred, &state)
        .map_err(|e| bad(format!("the passkey was not accepted: {e}")))?;
    // The invite is consumed only once the passkey is valid.
    if app.db.invite_pending(invite_id)?.is_none() {
        return Err(bad("this invitation was already used"));
    }
    let admin = match app.db.admin_by_email(&email)? {
        Some(a) if a.disabled => return Err(bad("this administrator is disabled")),
        Some(a) => a,
        None => app.db.create_admin(&name, &email)?,
    };
    let pk_name = if body.passkey_name.trim().is_empty() {
        "first passkey".to_string()
    } else {
        body.passkey_name.trim().chars().take(60).collect()
    };
    app.db.add_passkey(
        &admin.id,
        &pk_name,
        passkey.cred_id().as_ref(),
        &serde_json::to_string(&passkey)?,
    )?;
    app.db.use_invite(invite_id)?;
    app.db.audit(
        &admin.email,
        "admin.joined",
        &admin.email,
        json!({ "passkey": pk_name }),
        &c.ip,
    )?;
    let cookie = start_session(&app, &admin, &c).await?;
    Ok((
        [(header::SET_COOKIE, cookie)],
        Json(json!({ "ok": true, "admin": admin })),
    )
        .into_response())
}

async fn logout(State(app): State<App>, ext: axum::http::Extensions) -> Result<Response, ApiError> {
    if let Some(s) = ext.get::<Session>() {
        app.db.delete_session(&s.token_hash)?;
    }
    Ok((
        [(header::SET_COOKIE, set_cookie(&app, None))],
        Json(json!({ "ok": true })),
    )
        .into_response())
}

async fn me(State(app): State<App>, ext: axum::http::Extensions) -> ApiResult {
    match ext.get::<Session>() {
        Some(s) => Ok(Json(
            json!({ "admin": s.admin, "base": app.cfg.base, "origin": app.cfg.origin.as_str() }),
        )),
        None => Ok(Json(json!({ "admin": null, "base": app.cfg.base }))),
    }
}

async fn health(State(app): State<App>, ext: axum::http::Extensions) -> ApiResult {
    session(&ext)?;
    let h = app.garage.health().await?;
    Ok(Json(serde_json::to_value(h)?))
}

// ---------------------------------------------------------------- passkeys of the signed-in admin

async fn passkeys(State(app): State<App>, ext: axum::http::Extensions) -> ApiResult {
    let s = session(&ext)?;
    Ok(Json(serde_json::to_value(
        app.db.passkeys_of(&s.admin.id)?,
    )?))
}

async fn passkey_begin(State(app): State<App>, ext: axum::http::Extensions) -> ApiResult {
    let s = session(&ext)?;
    let existing: Vec<CredentialID> = app
        .db
        .passkeys_of(&s.admin.id)?
        .iter()
        .filter_map(|r| serde_json::from_str::<Passkey>(&r.passkey_json).ok())
        .map(|p| p.cred_id().clone())
        .collect();
    let (ccr, state) = app
        .webauthn
        .start_passkey_registration(
            Uuid::new_v4(),
            &s.admin.email,
            &s.admin.name,
            Some(existing),
        )
        .map_err(|e| bad(e.to_string()))?;
    let id = app.put_pending(Pending::AddPasskey {
        admin_id: s.admin.id.clone(),
        state,
    });
    Ok(Json(json!({ "challenge_id": id, "options": ccr })))
}

async fn passkey_finish(
    State(app): State<App>,
    ext: axum::http::Extensions,
    Json(body): Json<Finish>,
) -> ApiResult {
    let s = session(&ext)?;
    let c = ctx(&ext);
    let Some(Pending::AddPasskey { admin_id, state }) = app.take_pending(&body.challenge_id) else {
        return Err(bad("the registration challenge expired; try again"));
    };
    if admin_id != s.admin.id {
        return Err(unauthorized());
    }
    let cred: RegisterPublicKeyCredential =
        serde_json::from_value(body.credential).map_err(|e| bad(format!("bad credential: {e}")))?;
    let passkey = app
        .webauthn
        .finish_passkey_registration(&cred, &state)
        .map_err(|e| bad(format!("the passkey was not accepted: {e}")))?;
    let name: String = if body.passkey_name.trim().is_empty() {
        "passkey".into()
    } else {
        body.passkey_name.trim().chars().take(60).collect()
    };
    let id = app.db.add_passkey(
        &s.admin.id,
        &name,
        passkey.cred_id().as_ref(),
        &serde_json::to_string(&passkey)?,
    )?;
    app.db.audit(
        &s.admin.email,
        "passkey.added",
        &name,
        json!({ "id": id }),
        &c.ip,
    )?;
    Ok(Json(json!({ "ok": true, "id": id })))
}

async fn passkey_delete(
    State(app): State<App>,
    ext: axum::http::Extensions,
    Path(id): Path<i64>,
) -> ApiResult {
    let s = session(&ext)?;
    let c = ctx(&ext);
    if app.db.passkeys_of(&s.admin.id)?.len() <= 1 {
        return Err(bad("keep at least one passkey, or you lock yourself out"));
    }
    if !app.db.delete_passkey(&s.admin.id, id)? {
        return Err(ApiError(StatusCode::NOT_FOUND, "no such passkey".into()));
    }
    app.db.audit(
        &s.admin.email,
        "passkey.removed",
        &id.to_string(),
        json!({}),
        &c.ip,
    )?;
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------- admins

async fn admins(State(app): State<App>, ext: axum::http::Extensions) -> ApiResult {
    session(&ext)?;
    let admins = app.db.admins()?;
    let invites = app.db.invites()?;
    Ok(Json(json!({ "admins": admins, "invites": invites })))
}

#[derive(Deserialize)]
struct InviteReq {
    name: String,
    email: String,
}

async fn admin_invite(
    State(app): State<App>,
    ext: axum::http::Extensions,
    Json(body): Json<InviteReq>,
) -> ApiResult {
    let s = session(&ext)?;
    let c = ctx(&ext);
    let (url, invite) = crate::invite::create(&app, &body.name, &body.email, &s.admin.email, 24)?;
    app.db.audit(
        &s.admin.email,
        "admin.invited",
        &invite.email,
        json!({ "name": invite.name, "expires_at": invite.expires_at }),
        &c.ip,
    )?;
    Ok(Json(json!({ "url": url, "expires_at": invite.expires_at })))
}

async fn admin_disable(
    State(app): State<App>,
    ext: axum::http::Extensions,
    Path(id): Path<String>,
) -> ApiResult {
    let s = session(&ext)?;
    let c = ctx(&ext);
    if id == s.admin.id {
        return Err(bad("you cannot disable yourself"));
    }
    let target = app
        .db
        .admin_by_id(&id)?
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "no such administrator".into()))?;
    app.db.set_admin_disabled(&id, true)?;
    app.db.audit(
        &s.admin.email,
        "admin.disabled",
        &target.email,
        json!({}),
        &c.ip,
    )?;
    Ok(Json(json!({ "ok": true })))
}

async fn admin_enable(
    State(app): State<App>,
    ext: axum::http::Extensions,
    Path(id): Path<String>,
) -> ApiResult {
    let s = session(&ext)?;
    let c = ctx(&ext);
    let target = app
        .db
        .admin_by_id(&id)?
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "no such administrator".into()))?;
    app.db.set_admin_disabled(&id, false)?;
    app.db.audit(
        &s.admin.email,
        "admin.enabled",
        &target.email,
        json!({}),
        &c.ip,
    )?;
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------- buckets

async fn buckets(State(app): State<App>, ext: axum::http::Extensions) -> ApiResult {
    session(&ext)?;
    let list = app.garage.list_buckets().await?;
    let mut out = Vec::with_capacity(list.len());
    for b in list {
        match app.garage.bucket_info(&b.id).await {
            Ok(info) => out.push(serde_json::to_value(&info)?),
            Err(e) => out.push(json!({ "id": b.id, "globalAliases": b.global_aliases, "created": b.created, "error": e.to_string() })),
        }
    }
    out.sort_by_key(|v| {
        v.get("globalAliases")
            .and_then(|a| a.get(0))
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string()
    });
    Ok(Json(Value::Array(out)))
}

async fn bucket(
    State(app): State<App>,
    ext: axum::http::Extensions,
    Path(id): Path<String>,
) -> ApiResult {
    session(&ext)?;
    Ok(Json(serde_json::to_value(
        app.garage.bucket_info(&id).await?,
    )?))
}

#[derive(Deserialize)]
struct CreateBucket {
    name: String,
    /// Also create a read-write key named after the bucket, and a read-only one.
    #[serde(default)]
    with_keys: bool,
}

async fn create_bucket(
    State(app): State<App>,
    ext: axum::http::Extensions,
    Json(body): Json<CreateBucket>,
) -> ApiResult {
    let s = session(&ext)?;
    let c = ctx(&ext);
    let name = body.name.trim().to_string();
    valid_bucket_name(&name).map_err(bad)?;
    if app.garage.bucket_by_alias(&name).await?.is_some() {
        return Err(bad(format!("bucket '{name}' already exists")));
    }
    let info = app.garage.create_bucket(&name).await?;
    app.db.audit(
        &s.admin.email,
        "bucket.created",
        &name,
        json!({ "id": info.id }),
        &c.ip,
    )?;
    let mut keys = Vec::new();
    if body.with_keys {
        for (suffix, perm) in [
            (
                "",
                Perm {
                    read: true,
                    write: true,
                    owner: false,
                },
            ),
            (
                "-leitura",
                Perm {
                    read: true,
                    write: false,
                    owner: false,
                },
            ),
        ] {
            let key_name = format!("{name}{suffix}");
            let k = app.garage.create_key(&key_name).await?;
            app.garage.allow(&info.id, &k.access_key_id, &perm).await?;
            app.db.audit(
                &s.admin.email,
                "key.created",
                &key_name,
                json!({ "access_key_id": k.access_key_id, "bucket": name, "permissions": perm }),
                &c.ip,
            )?;
            keys.push(json!({ "name": key_name, "accessKeyId": k.access_key_id, "secretAccessKey": k.secret_access_key, "permissions": perm }));
        }
    }
    let info = app.garage.bucket_info(&info.id).await?;
    Ok(Json(json!({ "bucket": info, "keys": keys })))
}

#[derive(Deserialize)]
struct Confirm {
    #[serde(default)]
    name: String,
    /// On bucket deletion: also delete the keys whose only bucket this was.
    #[serde(default)]
    delete_orphan_keys: bool,
}

async fn delete_bucket(
    State(app): State<App>,
    ext: axum::http::Extensions,
    Path(id): Path<String>,
    Json(body): Json<Confirm>,
) -> ApiResult {
    let s = session(&ext)?;
    let c = ctx(&ext);
    let info = app.garage.bucket_info(&id).await?;
    if body.name.trim() != info.name() {
        return Err(bad("type the bucket's name to confirm"));
    }
    if info.objects > 0 {
        return Err(bad(format!(
            "bucket '{}' still has {} object(s); empty it first",
            info.name(),
            info.objects
        )));
    }
    let mut deleted_keys = Vec::new();
    for k in &info.keys {
        let only_this = body.delete_orphan_keys
            && app
                .garage
                .key_info(&k.access_key_id, false)
                .await
                .map(|ki| ki.buckets.iter().all(|b| b.id == id))
                .unwrap_or(false);
        app.garage.deny(&id, &k.access_key_id).await?;
        if only_this {
            app.garage.delete_key(&k.access_key_id).await?;
            app.db.audit(
                &s.admin.email,
                "key.deleted",
                &k.name,
                json!({ "access_key_id": k.access_key_id, "with_bucket": info.name() }),
                &c.ip,
            )?;
            deleted_keys.push(k.name.clone());
        }
    }
    app.garage.delete_bucket(&id).await?;
    app.db.audit(
        &s.admin.email,
        "bucket.deleted",
        &info.name(),
        json!({ "id": id, "deleted_keys": deleted_keys }),
        &c.ip,
    )?;
    Ok(Json(json!({ "ok": true, "deleted_keys": deleted_keys })))
}

#[derive(Deserialize)]
struct AllowReq {
    key_id: String,
    /// "read" or "readwrite"
    profile: String,
}

fn perm_of(profile: &str) -> Result<Perm, ApiError> {
    match profile {
        "read" => Ok(Perm {
            read: true,
            write: false,
            owner: false,
        }),
        "readwrite" => Ok(Perm {
            read: true,
            write: true,
            owner: false,
        }),
        _ => Err(bad("profile must be read or readwrite")),
    }
}

async fn allow_key(
    State(app): State<App>,
    ext: axum::http::Extensions,
    Path(id): Path<String>,
    Json(body): Json<AllowReq>,
) -> ApiResult {
    let s = session(&ext)?;
    let c = ctx(&ext);
    let perm = perm_of(&body.profile)?;
    let info = app.garage.bucket_info(&id).await?;
    let key = app.garage.key_info(&body.key_id, false).await?;
    // Allow is additive in Garage: deny first so "read" after "readwrite" really narrows.
    app.garage.deny(&id, &body.key_id).await?;
    let info2 = app.garage.allow(&id, &body.key_id, &perm).await?;
    app.db.audit(
        &s.admin.email,
        "bucket.key.allowed",
        &info.name(),
        json!({ "key": key.name, "access_key_id": body.key_id, "permissions": perm }),
        &c.ip,
    )?;
    Ok(Json(serde_json::to_value(info2)?))
}

#[derive(Deserialize)]
struct DenyReq {
    key_id: String,
}

async fn deny_key(
    State(app): State<App>,
    ext: axum::http::Extensions,
    Path(id): Path<String>,
    Json(body): Json<DenyReq>,
) -> ApiResult {
    let s = session(&ext)?;
    let c = ctx(&ext);
    let info = app.garage.bucket_info(&id).await?;
    let key = app.garage.key_info(&body.key_id, false).await?;
    let info2 = app.garage.deny(&id, &body.key_id).await?;
    app.db.audit(
        &s.admin.email,
        "bucket.key.denied",
        &info.name(),
        json!({ "key": key.name, "access_key_id": body.key_id }),
        &c.ip,
    )?;
    Ok(Json(serde_json::to_value(info2)?))
}

// ---------------------------------------------------------------- keys

async fn keys(State(app): State<App>, ext: axum::http::Extensions) -> ApiResult {
    session(&ext)?;
    let list = app.garage.list_keys().await?;
    let mut out = Vec::with_capacity(list.len());
    for k in list {
        match app.garage.key_info(&k.id, false).await {
            Ok(info) => out.push(serde_json::to_value(&info)?),
            Err(e) => {
                out.push(json!({ "accessKeyId": k.id, "name": k.name, "error": e.to_string() }))
            }
        }
    }
    out.sort_by_key(|v| {
        v.get("name")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string()
    });
    Ok(Json(Value::Array(out)))
}

async fn key(
    State(app): State<App>,
    ext: axum::http::Extensions,
    Path(id): Path<String>,
) -> ApiResult {
    session(&ext)?;
    Ok(Json(serde_json::to_value(
        app.garage.key_info(&id, false).await?,
    )?))
}

#[derive(Deserialize)]
struct CreateKey {
    name: String,
    #[serde(default)]
    bucket_id: String,
    #[serde(default = "default_profile")]
    profile: String,
}

fn default_profile() -> String {
    "read".into()
}

async fn create_key(
    State(app): State<App>,
    ext: axum::http::Extensions,
    Json(body): Json<CreateKey>,
) -> ApiResult {
    let s = session(&ext)?;
    let c = ctx(&ext);
    let name = body.name.trim().to_string();
    valid_key_name(&name).map_err(bad)?;
    if app.garage.list_keys().await?.iter().any(|k| k.name == name) {
        return Err(bad(format!("a key named '{name}' already exists")));
    }
    let perm = perm_of(&body.profile)?;
    let k = app.garage.create_key(&name).await?;
    let mut bucket_name = String::new();
    if !body.bucket_id.is_empty() {
        let info = app.garage.bucket_info(&body.bucket_id).await?;
        bucket_name = info.name();
        app.garage
            .allow(&body.bucket_id, &k.access_key_id, &perm)
            .await?;
    }
    app.db.audit(
        &s.admin.email,
        "key.created",
        &name,
        json!({ "access_key_id": k.access_key_id, "bucket": bucket_name, "permissions": perm }),
        &c.ip,
    )?;
    // The secret is shown once, here, and never stored by the console.
    Ok(Json(
        json!({ "name": name, "accessKeyId": k.access_key_id, "secretAccessKey": k.secret_access_key, "bucket": bucket_name, "permissions": perm }),
    ))
}

async fn delete_key(
    State(app): State<App>,
    ext: axum::http::Extensions,
    Path(id): Path<String>,
    Json(body): Json<Confirm>,
) -> ApiResult {
    let s = session(&ext)?;
    let c = ctx(&ext);
    let info = app.garage.key_info(&id, false).await?;
    if body.name.trim() != info.name {
        return Err(bad("type the key's name to confirm"));
    }
    app.garage.delete_key(&id).await?;
    app.db.audit(
        &s.admin.email,
        "key.deleted",
        &info.name,
        json!({ "access_key_id": id }),
        &c.ip,
    )?;
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------- audit

#[derive(Deserialize)]
struct AuditQuery {
    #[serde(default = "default_limit")]
    limit: i64,
}

fn default_limit() -> i64 {
    200
}

async fn audit(
    State(app): State<App>,
    ext: axum::http::Extensions,
    Query(q): Query<AuditQuery>,
) -> ApiResult {
    session(&ext)?;
    Ok(Json(serde_json::to_value(app.db.audit_entries(q.limit)?)?))
}
