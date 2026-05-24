//! Port of `RoleBootstrap.java` — ensures `user` and `admin` exist, and
//! that the parent edge `admin → user` is wired.

use chrono::Utc;
use uuid::Uuid;

use crate::db::Db;
use crate::role::{Role, RoleRepository};

use super::lock;

pub async fn ensure_core_roles(db: &Db, roles: &RoleRepository) -> anyhow::Result<()> {
    let mut tx = db.begin().await?;
    lock::acquire(&mut tx).await?;
    tx.commit().await?;

    ensure_role(roles, "user", "Standard authenticated user").await?;
    ensure_role(roles, "admin", "Full administrative access").await?;

    let admin = roles.find_by_name("admin").await?;
    let user = roles.find_by_name("user").await?;
    if let (Some(admin), Some(user)) = (admin.as_ref(), user.as_ref()) {
        if admin.parent_id.is_none() {
            let _ = roles.set_parent(admin.id, Some(user.id)).await;
        }
    }
    Ok(())
}

async fn ensure_role(
    roles: &RoleRepository,
    name: &str,
    description: &str,
) -> anyhow::Result<()> {
    if roles.find_by_name(name).await?.is_some() {
        return Ok(());
    }
    let role = Role {
        id: Uuid::new_v4(),
        name: name.to_string(),
        description: Some(description.to_string()),
        parent_id: None,
        created_at: Utc::now().naive_utc(),
    };
    roles.persist(&role).await?;
    Ok(())
}
