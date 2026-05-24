//! Port of `WebAppClientBootstrap.java` — seeds two OAuth clients used by
//! local dev: `web-app` (public SPA) and `service-client` (confidential M2M).
//!
//! Also performs a **one-time migration** of any pre-hashing
//! `service-client` row that still has the literal bootstrap secret as
//! plaintext — upgrades it to Argon2id at rest.

use chrono::Utc;
use uuid::Uuid;

use crate::client::{Client, ClientRepository, ClientSecretHasher, RedirectUri};
use crate::db::Db;

use super::lock;

const SERVICE_CLIENT_BOOTSTRAP_SECRET: &str = "service-secret-change-me";

pub async fn ensure_bootstrap_clients(
    db: &Db,
    clients: &ClientRepository,
) -> anyhow::Result<()> {
    let mut tx = db.begin().await?;
    lock::acquire(&mut tx).await?;
    tx.commit().await?;

    ensure_web_app(clients).await?;
    ensure_service_client(db, clients).await?;
    Ok(())
}

async fn ensure_web_app(clients: &ClientRepository) -> anyhow::Result<()> {
    if clients.find_by_client_id("web-app").await?.is_some() {
        return Ok(());
    }
    let now = Utc::now().naive_utc();
    let client = Client {
        id: Uuid::new_v4(),
        client_id: "web-app".to_string(),
        client_secret: None,
        name: Some("Web App".to_string()),
        client_type: Some("public".to_string()),
        grant_types: Some("authorization_code refresh_token".to_string()),
        response_types: Some("code".to_string()),
        scopes: Some("openid profile email".to_string()),
        pkce_required: true,
        enabled: true,
        base_url: Some("http://localhost:3000".to_string()),
        description: Some("Bootstrap public client for local OAuth testing".to_string()),
        access_token_ttl: Some(900),
        refresh_token_ttl: Some(2_592_000),
        frontchannel_logout_uri: None,
        backchannel_logout_uri: None,
        created_at: now,
        updated_at: now,
        redirect_uris: vec![RedirectUri {
            id: Uuid::new_v4(),
            client_id: Uuid::nil(), // overwritten by persist() — it sees the parent id
            uri: "http://localhost:3000/callback".to_string(),
            created_at: now,
        }],
    };
    // Patch the redirect_uri rows so their FK matches the parent we just minted.
    let parent_id = client.id;
    let client = Client {
        redirect_uris: client
            .redirect_uris
            .into_iter()
            .map(|r| RedirectUri {
                client_id: parent_id,
                ..r
            })
            .collect(),
        ..client
    };
    clients.persist(&client).await?;
    Ok(())
}

async fn ensure_service_client(db: &Db, clients: &ClientRepository) -> anyhow::Result<()> {
    if let Some(existing) = clients.find_by_client_id("service-client").await? {
        // One-time legacy plaintext migration. Detect the literal bootstrap
        // secret and upgrade to Argon2 in place — matches Java exactly.
        if existing.client_secret.as_deref() == Some(SERVICE_CLIENT_BOOTSTRAP_SECRET) {
            let hashed = ClientSecretHasher::hash(SERVICE_CLIENT_BOOTSTRAP_SECRET);
            sqlx::query(
                "UPDATE clients SET client_secret = $2, updated_at = NOW() WHERE id = $1",
            )
            .bind(existing.id)
            .bind(&hashed)
            .execute(db)
            .await?;
            clients.invalidate(&existing.client_id).await;
            tracing::info!("migrated service-client legacy plaintext bootstrap secret to Argon2 hash");
        } else if let Some(ref s) = existing.client_secret {
            if !s.is_empty() && !ClientSecretHasher::is_hashed(s) {
                tracing::warn!(
                    client_id = %existing.client_id,
                    "client has a plaintext secret — admin should rotate via /admin/clients/{{id}}"
                );
            }
        }
        return Ok(());
    }

    let now = Utc::now().naive_utc();
    let client = Client {
        id: Uuid::new_v4(),
        client_id: "service-client".to_string(),
        client_secret: Some(ClientSecretHasher::hash(SERVICE_CLIENT_BOOTSTRAP_SECRET)),
        name: Some("Service Client".to_string()),
        client_type: Some("confidential".to_string()),
        grant_types: Some("client_credentials".to_string()),
        response_types: Some(String::new()),
        scopes: Some("openid profile email".to_string()),
        pkce_required: false,
        enabled: true,
        base_url: None,
        description: Some(
            "Confidential client for machine-to-machine (client_credentials)".to_string(),
        ),
        access_token_ttl: Some(900),
        refresh_token_ttl: Some(0),
        frontchannel_logout_uri: None,
        backchannel_logout_uri: None,
        created_at: now,
        updated_at: now,
        redirect_uris: Vec::new(),
    };
    clients.persist(&client).await?;
    Ok(())
}
