//! Port of `AdminBootstrap.java` — seeds `admin@gmail.com` / `admin123`
//! with Argon2id-hashed password + assigns the `admin` role. Idempotent.

use chrono::Utc;
use uuid::Uuid;

use crate::common::crypto::argon2 as argon2_hasher;
use crate::db::Db;
use crate::role::RoleRepository;
use crate::user::{Credential, CredentialRepository, User, UserRepository};

use super::lock;

pub async fn ensure_admin_user(
    db: &Db,
    users: &UserRepository,
    credentials: &CredentialRepository,
    roles: &RoleRepository,
) -> anyhow::Result<()> {
    let mut tx = db.begin().await?;
    lock::acquire(&mut tx).await?;
    tx.commit().await?;

    let user = match users.find_by_email("admin@gmail.com").await? {
        Some(u) => u,
        None => create_admin_user(users, credentials).await?,
    };

    let admin_role = roles
        .find_by_name("admin")
        .await?
        .ok_or_else(|| anyhow::anyhow!("admin role missing after bootstrap"))?;
    if !roles.is_assigned(user.id, admin_role.id).await? {
        roles.assign_to_user(user.id, admin_role.id).await?;
    }
    Ok(())
}

async fn create_admin_user(
    users: &UserRepository,
    credentials: &CredentialRepository,
) -> anyhow::Result<User> {
    let now = Utc::now().naive_utc();
    let user = User {
        id: Uuid::new_v4(),
        email: "admin@gmail.com".to_string(),
        email_verified: true,
        username: "admin".to_string(),
        first_name: Some("Admin".to_string()),
        last_name: Some("User".to_string()),
        enabled: true,
        created_at: now,
        updated_at: now,
    };
    users.persist(&user).await?;

    let hashed = argon2_hasher::hash("admin123");
    let credential = Credential {
        id: Uuid::new_v4(),
        credential_type: "password".to_string(),
        secret_data: Some(hashed.secret_data),
        credential_data: Some(hashed.credential_data),
        created_at: now,
        updated_at: now,
        user_id: user.id,
    };
    credentials.persist(&credential).await?;
    Ok(user)
}
