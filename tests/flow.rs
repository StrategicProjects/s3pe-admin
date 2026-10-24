//! End to end over HTTP: a fake Garage admin API, a software passkey, and
//! the whole console flow (invite, sign in, buckets, keys, audit, CSRF).

use axum::extract::{Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use url::Url;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse};

// ----------------------------------------------------------------- fake Garage

#[derive(Default)]
struct FakeGarage {
    buckets: HashMap<String, Value>,
    keys: HashMap<String, Value>,
    n: u32,
}

type FG = Arc<Mutex<FakeGarage>>;

fn bucket_view(b: &Value, keys: &HashMap<String, Value>) -> Value {
    let mut v = b.clone();
    let id = b["id"].as_str().unwrap();
    let ks: Vec<Value> = keys
        .values()
        .filter_map(|k| {
            k["buckets"].as_array().unwrap().iter().find(|x| x["id"] == id).map(|x| {
                json!({ "accessKeyId": k["accessKeyId"], "name": k["name"], "permissions": x["permissions"], "bucketLocalAliases": [] })
            })
        })
        .collect();
    v["keys"] = Value::Array(ks);
    v
}

async fn fake_garage() -> (String, FG) {
    let fg: FG = Arc::new(Mutex::new(FakeGarage::default()));
    let app = Router::new()
        .route("/v2/GetClusterHealth", get(|| async { Json(json!({"status":"healthy","knownNodes":1,"connectedNodes":1,"storageNodes":1,"storageNodesUp":1,"partitions":256,"partitionsQuorum":256,"partitionsAllOk":256})) }))
        .route("/v2/ListBuckets", get(|State(fg): State<FG>| async move {
            let g = fg.lock().unwrap();
            Json(Value::Array(g.buckets.values().map(|b| json!({"id": b["id"], "created": b["created"], "globalAliases": b["globalAliases"], "localAliases": []})).collect()))
        }))
        .route("/v2/GetBucketInfo", get(|State(fg): State<FG>, Query(q): Query<HashMap<String, String>>| async move {
            let g = fg.lock().unwrap();
            let found = g.buckets.values().find(|b| q.get("id").map(|id| b["id"] == *id).unwrap_or(false) || q.get("globalAlias").map(|a| b["globalAliases"][0] == *a).unwrap_or(false));
            match found { Some(b) => (axum::http::StatusCode::OK, Json(bucket_view(b, &g.keys))), None => (axum::http::StatusCode::NOT_FOUND, Json(json!({"code":"NoSuchBucket","message":"no such bucket"}))) }
        }))
        .route("/v2/CreateBucket", post(|State(fg): State<FG>, Json(b): Json<Value>| async move {
            let mut g = fg.lock().unwrap();
            g.n += 1;
            let id = format!("bucket{:02}{}", g.n, "0".repeat(56));
            let v = json!({"id": id, "created": "2026-10-24T00:00:00Z", "globalAliases": [b["globalAlias"]], "websiteAccess": false, "keys": [], "objects": 0, "bytes": 0, "unfinishedUploads": 0, "unfinishedMultipartUploads": 0, "unfinishedMultipartUploadParts": 0, "unfinishedMultipartUploadBytes": 0, "quotas": {"maxSize": null, "maxObjects": null}});
            g.buckets.insert(id, v.clone());
            Json(v)
        }))
        .route("/v2/DeleteBucket", post(|State(fg): State<FG>, Query(q): Query<HashMap<String, String>>| async move {
            fg.lock().unwrap().buckets.remove(&q["id"]);
            axum::http::StatusCode::NO_CONTENT
        }))
        .route("/v2/ListKeys", get(|State(fg): State<FG>| async move {
            let g = fg.lock().unwrap();
            Json(Value::Array(g.keys.values().map(|k| json!({"id": k["accessKeyId"], "name": k["name"], "expired": false, "created": k["created"]})).collect()))
        }))
        .route("/v2/GetKeyInfo", get(|State(fg): State<FG>, Query(q): Query<HashMap<String, String>>| async move {
            let g = fg.lock().unwrap();
            match g.keys.get(&q["id"]) {
                Some(k) => { let mut v = k.clone(); if q.get("showSecretKey").map(|s| s == "true").unwrap_or(false) { v["secretAccessKey"] = json!("secret-of-the-fake"); } else { v["secretAccessKey"] = Value::Null; } (axum::http::StatusCode::OK, Json(v)) }
                None => (axum::http::StatusCode::NOT_FOUND, Json(json!({"message":"no such key"}))),
            }
        }))
        .route("/v2/CreateKey", post(|State(fg): State<FG>, Json(b): Json<Value>| async move {
            let mut g = fg.lock().unwrap();
            g.n += 1;
            let id = format!("GK{:024}", g.n);
            let v = json!({"accessKeyId": id, "name": b["name"], "created": "2026-10-24T00:00:00Z", "expiration": null, "expired": false, "permissions": {"createBucket": false}, "buckets": [], "secretAccessKey": "secret-of-the-fake"});
            g.keys.insert(id, v.clone());
            Json(v)
        }))
        .route("/v2/DeleteKey", post(|State(fg): State<FG>, Query(q): Query<HashMap<String, String>>| async move {
            fg.lock().unwrap().keys.remove(&q["id"]);
            axum::http::StatusCode::NO_CONTENT
        }))
        .route("/v2/AllowBucketKey", post(|State(fg): State<FG>, Json(b): Json<Value>| async move {
            let mut g = fg.lock().unwrap();
            let bucket = g.buckets[b["bucketId"].as_str().unwrap()].clone();
            let key = g.keys.get_mut(b["accessKeyId"].as_str().unwrap()).unwrap();
            let arr = key["buckets"].as_array_mut().unwrap();
            arr.retain(|x| x["id"] != b["bucketId"]);
            arr.push(json!({"id": b["bucketId"], "globalAliases": bucket["globalAliases"], "localAliases": [], "permissions": b["permissions"]}));
            Json(bucket_view(&bucket, &g.keys))
        }))
        .route("/v2/DenyBucketKey", post(|State(fg): State<FG>, Json(b): Json<Value>| async move {
            let mut g = fg.lock().unwrap();
            let bucket = g.buckets[b["bucketId"].as_str().unwrap()].clone();
            if let Some(key) = g.keys.get_mut(b["accessKeyId"].as_str().unwrap()) { key["buckets"].as_array_mut().unwrap().retain(|x| x["id"] != b["bucketId"]); }
            Json(bucket_view(&bucket, &g.keys))
        }))
        .with_state(fg.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}"), fg)
}

// ----------------------------------------------------------------- the console under test

struct Console {
    url: String,
    base: String,
    cookie: Option<String>,
    http: reqwest::Client,
    invite_token: String,
}

impl Console {
    async fn start(garage_url: &str) -> Console {
        let dir = std::env::temp_dir().join(format!("s3pe-admin-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let origin = format!("http://localhost:{}", addr.port());
        // The console is a binary crate: drive it through the environment + its modules.
        std::env::set_var("S3PE_ADMIN_ORIGIN", &origin);
        std::env::set_var("S3PE_ADMIN_BASE", "/admin");
        std::env::set_var("S3PE_ADMIN_DB", dir.join("admin.db"));
        std::env::set_var("GARAGE_ADMIN_URL", garage_url);
        std::env::set_var("GARAGE_ADMIN_TOKEN", "test-token");
        let cfg = s3pe_admin::state::Config::from_env().unwrap();
        let db = s3pe_admin::db::Db::open(&cfg.db_path).unwrap();
        let app = s3pe_admin::state::AppState::new(cfg, db).unwrap();
        let app2 = app.clone();
        tokio::spawn(async move {
            axum::serve(
                listener,
                s3pe_admin::web::router(app2).into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        // an invitation from the CLI path
        let (url, _) =
            s3pe_admin::invite::create(&app, "Ana Admin", "ana@example.org", "cli", 24).unwrap();
        let token = url.split("#invite=").nth(1).unwrap().to_string();
        Console {
            url: origin.clone(),
            base: "/admin".into(),
            cookie: None,
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            invite_token: token,
        }
    }
}

async fn call(
    c: &mut Console,
    method: &str,
    path: &str,
    body: Option<Value>,
    with_marker: bool,
) -> (u16, Value) {
    let mut req = match method {
        "GET" => c.http.get(format!("{}{}/api{}", c.url, c.base, path)),
        _ => c.http.post(format!("{}{}/api{}", c.url, c.base, path)),
    };
    if with_marker {
        req = req
            .header("X-Requested-With", "s3pe-admin")
            .header("Origin", &c.url);
    }
    if let Some(ck) = &c.cookie {
        req = req.header("Cookie", format!("s3pe_admin={ck}"));
    }
    if let Some(b) = body {
        req = req.json(&b);
    }
    let resp = req.send().await.unwrap();
    if let Some(sc) = resp
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
    {
        let v = sc
            .split(';')
            .next()
            .unwrap()
            .trim_start_matches("s3pe_admin=")
            .to_string();
        c.cookie = if v.is_empty() { None } else { Some(v) };
        assert!(
            sc.contains("HttpOnly") && sc.contains("SameSite=Strict") && sc.contains("Path=/admin"),
            "{sc}"
        );
    }
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap();
    (status, serde_json::from_str(&text).unwrap_or(Value::Null))
}

#[tokio::test]
async fn invite_login_and_manage() {
    let (garage_url, fg) = fake_garage().await;
    let mut c = Console::start(&garage_url).await;
    let origin = Url::parse(&c.url).unwrap();
    let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));

    // security headers on the page
    let page = c
        .http
        .get(format!("{}/admin/", c.url))
        .send()
        .await
        .unwrap();
    assert_eq!(page.status(), 200);
    assert!(page
        .headers()
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap()
        .contains("script-src 'self'"));
    assert_eq!(page.headers().get("x-frame-options").unwrap(), "DENY");
    let font = c
        .http
        .get(format!("{}/admin/fonts/saira.woff2", c.url))
        .send()
        .await
        .unwrap();
    assert_eq!(font.status(), 200);
    assert_eq!(font.headers().get("content-type").unwrap(), "font/woff2");
    assert!(font
        .headers()
        .get("cache-control")
        .unwrap()
        .to_str()
        .unwrap()
        .contains("max-age"));

    // not signed in
    let (s, v) = call(&mut c, "GET", "/me", None, false).await;
    assert_eq!(s, 200);
    assert!(v["admin"].is_null());
    let (s, _) = call(&mut c, "GET", "/buckets", None, false).await;
    assert_eq!(s, 401);

    // cross-site POST refused (no marker/origin)
    let (s, _) = call(
        &mut c,
        "POST",
        "/login/begin",
        Some(json!({"email": "x"})),
        false,
    )
    .await;
    assert_eq!(s, 403);

    // invitation → passkey registration → session
    let token = c.invite_token.clone();
    let (s, begin) = call(
        &mut c,
        "POST",
        "/invite/begin",
        Some(json!({"token": token})),
        true,
    )
    .await;
    assert_eq!(s, 200, "{begin}");
    assert_eq!(begin["email"], "ana@example.org");
    let ccr: CreationChallengeResponse = serde_json::from_value(begin["options"].clone()).unwrap();
    let reg = authenticator.do_registration(origin.clone(), ccr).unwrap();
    let (s, v) = call(&mut c, "POST", "/invite/finish", Some(json!({"challenge_id": begin["challenge_id"], "credential": reg, "passkey_name": "soft key"})), true).await;
    assert_eq!(s, 200, "{v}");
    assert!(c.cookie.is_some());
    let (s, _) = call(
        &mut c,
        "POST",
        "/invite/begin",
        Some(json!({"token": token})),
        true,
    )
    .await;
    assert_eq!(s, 400, "an invitation works once");

    // signed in
    let (_, v) = call(&mut c, "GET", "/me", None, false).await;
    assert_eq!(v["admin"]["email"], "ana@example.org");
    let (s, h) = call(&mut c, "GET", "/health", None, false).await;
    assert_eq!(s, 200);
    assert_eq!(h["status"], "healthy");

    // buckets and keys
    let (s, v) = call(
        &mut c,
        "POST",
        "/buckets",
        Some(json!({"name": "Admin", "with_keys": false})),
        true,
    )
    .await;
    assert_eq!(s, 400, "{v}");
    let (s, v) = call(
        &mut c,
        "POST",
        "/buckets",
        Some(json!({"name": "projeto", "with_keys": true})),
        true,
    )
    .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["keys"].as_array().unwrap().len(), 2);
    assert_eq!(v["keys"][0]["name"], "projeto");
    assert_eq!(v["keys"][0]["secretAccessKey"], "secret-of-the-fake");
    assert_eq!(v["keys"][1]["name"], "projeto-leitura");
    assert_eq!(v["keys"][1]["permissions"]["write"], false);
    let bucket_id = v["bucket"]["id"].as_str().unwrap().to_string();
    let (s, v) = call(
        &mut c,
        "POST",
        "/buckets",
        Some(json!({"name": "projeto"})),
        true,
    )
    .await;
    assert_eq!(s, 400, "duplicate: {v}");

    let (_, list) = call(&mut c, "GET", "/buckets", None, false).await;
    assert_eq!(list.as_array().unwrap().len(), 1);
    assert_eq!(list[0]["keys"].as_array().unwrap().len(), 2);

    let (s, k) = call(
        &mut c,
        "POST",
        "/keys",
        Some(json!({"name": "externo", "bucket_id": bucket_id, "profile": "read"})),
        true,
    )
    .await;
    assert_eq!(s, 200, "{k}");
    let key_id = k["accessKeyId"].as_str().unwrap().to_string();
    let (_, keys) = call(&mut c, "GET", "/keys", None, false).await;
    assert_eq!(keys.as_array().unwrap().len(), 3);
    assert!(
        keys.as_array()
            .unwrap()
            .iter()
            .all(|k| k["secretAccessKey"].is_null()),
        "secrets never listed"
    );

    let (s, b) = call(
        &mut c,
        "POST",
        &format!("/buckets/{bucket_id}/allow"),
        Some(json!({"key_id": key_id, "profile": "readwrite"})),
        true,
    )
    .await;
    assert_eq!(s, 200, "{b}");
    assert!(b["keys"]
        .as_array()
        .unwrap()
        .iter()
        .any(|k| k["accessKeyId"] == key_id && k["permissions"]["write"] == true));
    let (s, b) = call(
        &mut c,
        "POST",
        &format!("/buckets/{bucket_id}/deny"),
        Some(json!({"key_id": key_id})),
        true,
    )
    .await;
    assert_eq!(s, 200);
    assert!(!b["keys"]
        .as_array()
        .unwrap()
        .iter()
        .any(|k| k["accessKeyId"] == key_id));

    let (s, sec) = call(
        &mut c,
        "GET",
        &format!("/keys/{key_id}/secret"),
        None,
        false,
    )
    .await;
    assert_eq!(s, 200, "{sec}");
    assert_eq!(sec["secretAccessKey"], "secret-of-the-fake");
    let (s, rot) = call(
        &mut c,
        "POST",
        &format!("/keys/{key_id}/rotate"),
        Some(json!({"name": "externo"})),
        true,
    )
    .await;
    assert_eq!(s, 200, "{rot}");
    assert_ne!(rot["accessKeyId"], key_id, "a new key replaces the old one");
    assert!(
        fg.lock().unwrap().keys.get(&key_id).is_none(),
        "old key deleted"
    );
    let key_id = rot["accessKeyId"].as_str().unwrap().to_string();
    let (s, _) = call(
        &mut c,
        "POST",
        &format!("/keys/{key_id}/delete"),
        Some(json!({"name": "wrong"})),
        true,
    )
    .await;
    assert_eq!(s, 400);
    let (s, _) = call(
        &mut c,
        "POST",
        &format!("/keys/{key_id}/delete"),
        Some(json!({"name": "externo"})),
        true,
    )
    .await;
    assert_eq!(s, 200);

    let (s, v) = call(
        &mut c,
        "POST",
        &format!("/buckets/{bucket_id}/delete"),
        Some(json!({"name": "projeto", "delete_orphan_keys": true})),
        true,
    )
    .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(
        v["deleted_keys"].as_array().unwrap().len(),
        2,
        "the bucket's own keys go with it"
    );
    assert!(fg.lock().unwrap().buckets.is_empty());
    assert!(fg.lock().unwrap().keys.is_empty());

    // audit, admins, invitations from the UI
    let (_, audit) = call(&mut c, "GET", "/audit?limit=50", None, false).await;
    let actions: Vec<&str> = audit
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["action"].as_str().unwrap())
        .collect();
    for a in [
        "bucket.created",
        "key.created",
        "bucket.key.allowed",
        "bucket.key.denied",
        "key.deleted",
        "key.secret_revealed",
        "key.rotated",
        "bucket.deleted",
        "login",
        "admin.joined",
    ] {
        assert!(actions.contains(&a), "missing {a} in {actions:?}");
    }
    let (s, inv) = call(
        &mut c,
        "POST",
        "/admins/invite",
        Some(json!({"name": "Hugo", "email": "hugo@example.org"})),
        true,
    )
    .await;
    assert_eq!(s, 200, "{inv}");
    assert!(inv["url"].as_str().unwrap().contains("/admin/#invite="));
    let (_, admins) = call(&mut c, "GET", "/admins", None, false).await;
    assert_eq!(admins["admins"].as_array().unwrap().len(), 1);
    assert_eq!(admins["invites"].as_array().unwrap().len(), 2);

    // passkeys of the signed-in admin: a second one, then the first can be removed
    let (_, pks) = call(&mut c, "GET", "/passkeys", None, false).await;
    assert_eq!(pks.as_array().unwrap().len(), 1);
    let first_id = pks[0]["id"].as_i64().unwrap();
    let (s, _) = call(
        &mut c,
        "POST",
        &format!("/passkeys/{first_id}/delete"),
        Some(json!({})),
        true,
    )
    .await;
    assert_eq!(s, 400, "the last passkey stays");
    let (_, begin) = call(&mut c, "POST", "/passkeys/begin", Some(json!({})), true).await;
    let ccr: CreationChallengeResponse = serde_json::from_value(begin["options"].clone()).unwrap();
    let mut second = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let reg = second.do_registration(origin.clone(), ccr).unwrap();
    let (s, v) = call(&mut c, "POST", "/passkeys/finish", Some(json!({"challenge_id": begin["challenge_id"], "credential": reg, "passkey_name": "second"})), true).await;
    assert_eq!(s, 200, "{v}");
    let (s, _) = call(
        &mut c,
        "POST",
        &format!("/passkeys/{first_id}/delete"),
        Some(json!({})),
        true,
    )
    .await;
    assert_eq!(s, 200);

    // sign out, then sign in again with the second passkey
    let (s, _) = call(&mut c, "POST", "/logout", Some(json!({})), true).await;
    assert_eq!(s, 200);
    assert!(c.cookie.is_none());
    let (s, _) = call(&mut c, "GET", "/buckets", None, false).await;
    assert_eq!(s, 401);
    let (s, v) = call(
        &mut c,
        "POST",
        "/login/begin",
        Some(json!({"email": "nobody@example.org"})),
        true,
    )
    .await;
    assert_eq!(s, 401, "{v}");
    let (s, begin) = call(
        &mut c,
        "POST",
        "/login/begin",
        Some(json!({"email": "ana@example.org"})),
        true,
    )
    .await;
    assert_eq!(s, 200, "{begin}");
    let rcr: RequestChallengeResponse = serde_json::from_value(begin["options"].clone()).unwrap();
    let auth = second.do_authentication(origin.clone(), rcr).unwrap();
    let (s, v) = call(
        &mut c,
        "POST",
        "/login/finish",
        Some(json!({"challenge_id": begin["challenge_id"], "credential": auth})),
        true,
    )
    .await;
    assert_eq!(s, 200, "{v}");
    assert!(c.cookie.is_some());
    // the removed passkey cannot sign in
    let (_, begin) = call(
        &mut c,
        "POST",
        "/login/begin",
        Some(json!({"email": "ana@example.org"})),
        true,
    )
    .await;
    let rcr: RequestChallengeResponse = serde_json::from_value(begin["options"].clone()).unwrap();
    assert!(
        authenticator
            .do_authentication(origin.clone(), rcr)
            .is_err()
            || {
                let auth = authenticator
                    .do_authentication(
                        origin.clone(),
                        serde_json::from_value(begin["options"].clone()).unwrap(),
                    )
                    .unwrap();
                let (s, _) = call(
                    &mut c,
                    "POST",
                    "/login/finish",
                    Some(json!({"challenge_id": begin["challenge_id"], "credential": auth})),
                    true,
                )
                .await;
                s == 401
            }
    );

    // rate limit on authentication endpoints
    let mut last = 0;
    for _ in 0..25 {
        let (s, _) = call(
            &mut c,
            "POST",
            "/login/begin",
            Some(json!({"email": "nobody@example.org"})),
            true,
        )
        .await;
        last = s;
    }
    assert_eq!(last, 429);
}
