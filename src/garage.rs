//! Client of the Garage administration API v2 (bearer token, localhost).

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct Garage {
    http: reqwest::Client,
    base: String,
    token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Perm {
    #[serde(default)]
    pub read: bool,
    #[serde(default)]
    pub write: bool,
    #[serde(default)]
    pub owner: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BucketKey {
    pub access_key_id: String,
    pub name: String,
    pub permissions: Perm,
    #[serde(default)]
    pub bucket_local_aliases: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Quotas {
    pub max_size: Option<u64>,
    pub max_objects: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BucketInfo {
    pub id: String,
    pub created: String,
    pub global_aliases: Vec<String>,
    #[serde(default)]
    pub website_access: bool,
    pub keys: Vec<BucketKey>,
    #[serde(default)]
    pub objects: u64,
    #[serde(default)]
    pub bytes: u64,
    #[serde(default)]
    pub unfinished_uploads: u64,
    #[serde(default)]
    pub unfinished_multipart_uploads: u64,
    #[serde(default)]
    pub quotas: Quotas,
}

impl BucketInfo {
    pub fn name(&self) -> String {
        self.global_aliases
            .first()
            .cloned()
            .unwrap_or_else(|| self.id.chars().take(12).collect())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BucketListItem {
    pub id: String,
    pub created: String,
    pub global_aliases: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyListItem {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub expired: bool,
    pub created: Option<String>,
    pub expiration: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyBucket {
    pub id: String,
    pub global_aliases: Vec<String>,
    #[serde(default)]
    pub local_aliases: Vec<String>,
    pub permissions: Perm,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyInfo {
    pub access_key_id: String,
    pub name: String,
    pub created: Option<String>,
    pub expiration: Option<String>,
    #[serde(default)]
    pub expired: bool,
    pub secret_access_key: Option<String>,
    #[serde(default)]
    pub buckets: Vec<KeyBucket>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClusterHealth {
    pub status: String,
    pub known_nodes: u64,
    pub connected_nodes: u64,
    pub storage_nodes: u64,
    pub storage_nodes_up: u64,
    pub partitions: u64,
    pub partitions_quorum: u64,
    pub partitions_all_ok: u64,
}

impl Garage {
    pub fn new(base: &str, token: &str) -> Garage {
        Garage {
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(20))
                .build()
                .expect("reqwest client"),
            base: base.trim_end_matches('/').to_string(),
            token: token.trim().to_string(),
        }
    }

    async fn get<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        query: &[(&str, &str)],
    ) -> Result<T> {
        let resp = self
            .http
            .get(format!("{}{}", self.base, path))
            .bearer_auth(&self.token)
            .query(query)
            .send()
            .await
            .with_context(|| format!("GET {path}"))?;
        Self::decode(resp, path).await
    }

    async fn post<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        query: &[(&str, &str)],
        body: Option<serde_json::Value>,
    ) -> Result<T> {
        let mut req = self
            .http
            .post(format!("{}{}", self.base, path))
            .bearer_auth(&self.token)
            .query(query);
        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req.send().await.with_context(|| format!("POST {path}"))?;
        Self::decode(resp, path).await
    }

    async fn decode<T: for<'de> Deserialize<'de>>(
        resp: reqwest::Response,
        path: &str,
    ) -> Result<T> {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            let msg: String = serde_json::from_str::<serde_json::Value>(&text)
                .ok()
                .and_then(|v| {
                    v.get("message")
                        .and_then(|m| m.as_str())
                        .map(str::to_string)
                })
                .unwrap_or_else(|| text.chars().take(200).collect());
            return Err(anyhow!("Garage {path}: HTTP {} {}", status.as_u16(), msg));
        }
        if text.trim().is_empty() {
            serde_json::from_str("null").map_err(|e| anyhow!("Garage {path}: {e}"))
        } else {
            serde_json::from_str(&text).with_context(|| format!("Garage {path}: unexpected answer"))
        }
    }

    pub async fn health(&self) -> Result<ClusterHealth> {
        self.get("/v2/GetClusterHealth", &[]).await
    }

    pub async fn list_buckets(&self) -> Result<Vec<BucketListItem>> {
        self.get("/v2/ListBuckets", &[]).await
    }

    /// Every bucket with its full information, in one call (Garage ≥ 2.0).
    pub async fn list_buckets_info(&self) -> Result<Vec<BucketInfo>> {
        self.get("/v2/ListBucketsInfo", &[]).await
    }

    /// Every key with its buckets and permissions, in one call, secrets left out.
    pub async fn list_keys_info(&self) -> Result<Vec<KeyInfo>> {
        let mut keys: Vec<KeyInfo> = self.get("/v2/ListKeysInfo", &[]).await?;
        for k in &mut keys {
            k.secret_access_key = None;
        }
        Ok(keys)
    }

    pub async fn bucket_info(&self, id: &str) -> Result<BucketInfo> {
        self.get("/v2/GetBucketInfo", &[("id", id)]).await
    }

    pub async fn bucket_by_alias(&self, alias: &str) -> Result<Option<BucketInfo>> {
        match self
            .get::<BucketInfo>("/v2/GetBucketInfo", &[("globalAlias", alias)])
            .await
        {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.to_string().contains("HTTP 404") => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub async fn create_bucket(&self, alias: &str) -> Result<BucketInfo> {
        self.post(
            "/v2/CreateBucket",
            &[],
            Some(serde_json::json!({ "globalAlias": alias })),
        )
        .await
    }

    pub async fn delete_bucket(&self, id: &str) -> Result<()> {
        let _: serde_json::Value = self.post("/v2/DeleteBucket", &[("id", id)], None).await?;
        Ok(())
    }

    pub async fn list_keys(&self) -> Result<Vec<KeyListItem>> {
        self.get("/v2/ListKeys", &[]).await
    }

    pub async fn key_info(&self, id: &str, show_secret: bool) -> Result<KeyInfo> {
        self.get(
            "/v2/GetKeyInfo",
            &[
                ("id", id),
                ("showSecretKey", if show_secret { "true" } else { "false" }),
            ],
        )
        .await
    }

    pub async fn create_key(&self, name: &str) -> Result<KeyInfo> {
        self.post(
            "/v2/CreateKey",
            &[],
            Some(serde_json::json!({ "name": name, "neverExpires": true })),
        )
        .await
    }

    pub async fn delete_key(&self, id: &str) -> Result<()> {
        let _: serde_json::Value = self.post("/v2/DeleteKey", &[("id", id)], None).await?;
        Ok(())
    }

    pub async fn allow(&self, bucket_id: &str, key_id: &str, perm: &Perm) -> Result<BucketInfo> {
        self.post("/v2/AllowBucketKey", &[], Some(serde_json::json!({ "bucketId": bucket_id, "accessKeyId": key_id, "permissions": perm }))).await
    }

    pub async fn deny(&self, bucket_id: &str, key_id: &str) -> Result<BucketInfo> {
        let all = Perm {
            read: true,
            write: true,
            owner: true,
        };
        self.post("/v2/DenyBucketKey", &[], Some(serde_json::json!({ "bucketId": bucket_id, "accessKeyId": key_id, "permissions": all }))).await
    }
}

/// S3 bucket naming rules, plus names this console reserves.
pub fn valid_bucket_name(name: &str) -> std::result::Result<(), String> {
    let n = name.len();
    if !(3..=63).contains(&n) {
        return Err("the name must have 3 to 63 characters".into());
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
    {
        return Err("only lowercase letters, digits, '-' and '.'".into());
    }
    if !name.as_bytes()[0].is_ascii_alphanumeric()
        || !name.as_bytes()[n - 1].is_ascii_alphanumeric()
    {
        return Err("the name must start and end with a letter or digit".into());
    }
    if name.contains("..") || name.contains(".-") || name.contains("-.") {
        return Err("no '..', '.-' or '-.' in the name".into());
    }
    if name.split('.').count() == 4 && name.split('.').all(|p| p.parse::<u8>().is_ok()) {
        return Err("the name cannot look like an IP address".into());
    }
    if ["admin", "api", "health", "metrics", "static"].contains(&name)
        || name.starts_with("xn--")
        || name.ends_with("-s3alias")
    {
        return Err(format!("'{name}' is reserved"));
    }
    Ok(())
}

pub fn valid_key_name(name: &str) -> std::result::Result<(), String> {
    let n = name.len();
    if !(2..=64).contains(&n) {
        return Err("the key name must have 2 to 64 characters".into());
    }
    if !name.bytes().all(|b| {
        b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_' || b == b'.'
    }) {
        return Err("only lowercase letters, digits, '-', '_' and '.'".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_names() {
        assert!(valid_bucket_name("sds").is_ok());
        assert!(valid_bucket_name("horizonte-fiscal").is_ok());
        assert!(valid_bucket_name("Admin").is_err());
        assert!(valid_bucket_name("admin").is_err());
        assert!(valid_bucket_name("ab").is_err());
        assert!(valid_bucket_name("-abc").is_err());
        assert!(valid_bucket_name("a..b").is_err());
        assert!(valid_bucket_name("192.168.0.1").is_err());
        assert!(valid_key_name("sds-leitura").is_ok());
        assert!(valid_key_name("SDS").is_err());
    }
}
