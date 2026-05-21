//! Port of `com.xerika.auth.role.*` — the `Role` entity, the hierarchy
//! repository, and the cycle-detection error.
//!
//! Hierarchy semantics: roles form a forest via `parent_id`; effective roles
//! for a user are the directly-assigned ones **plus** all transitive
//! ancestors. `set_parent` is the only writer of `parent_id` and guards
//! against cycles inside a `FOR UPDATE` lock on the full roles table, same
//! as the Java `wouldCreateCycleLocked` path.

use std::collections::{HashMap, HashSet};

use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::db::Db;

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Role {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub parent_id: Option<Uuid>,
    pub created_at: NaiveDateTime,
}

#[derive(thiserror::Error, Debug)]
pub enum RoleError {
    #[error("cycle in role hierarchy: {0}")]
    Cycle(String),
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

#[derive(Clone)]
pub struct RoleRepository {
    db: Db,
}

impl RoleRepository {
    pub fn new(db: Db) -> Self {
        Self { db }
    }

    pub async fn find_by_name(&self, name: &str) -> sqlx::Result<Option<Role>> {
        sqlx::query_as::<_, Role>("SELECT * FROM roles WHERE name = $1")
            .bind(name)
            .fetch_optional(&self.db)
            .await
    }

    pub async fn find_all(&self) -> sqlx::Result<Vec<Role>> {
        sqlx::query_as::<_, Role>("SELECT * FROM roles ORDER BY name")
            .fetch_all(&self.db)
            .await
    }

    /// Role names directly attached to the user (no hierarchy walk).
    pub async fn find_names_by_user_id(&self, user_id: Uuid) -> sqlx::Result<Vec<String>> {
        let rows: Vec<(String,)> = sqlx::query_as(
            r#"SELECT r.name
               FROM roles r
               JOIN user_roles ur ON ur.role_id = r.id
               WHERE ur.user_id = $1"#,
        )
        .bind(user_id)
        .fetch_all(&self.db)
        .await?;
        Ok(rows.into_iter().map(|(n,)| n).collect())
    }

    /// Effective role names: direct assignments **plus** every ancestor
    /// reachable via `parent_id`. Matches `findEffectiveNamesByUserId` —
    /// order is "directly assigned first, then ancestors discovered via
    /// DFS", which is what JWT scopes and admin views key off.
    pub async fn find_effective_names_by_user_id(
        &self,
        user_id: Uuid,
    ) -> sqlx::Result<Vec<String>> {
        let direct: Vec<Role> = sqlx::query_as::<_, Role>(
            r#"SELECT r.*
               FROM roles r
               JOIN user_roles ur ON ur.role_id = r.id
               WHERE ur.user_id = $1"#,
        )
        .bind(user_id)
        .fetch_all(&self.db)
        .await?;

        let all_roles: Vec<Role> = sqlx::query_as::<_, Role>("SELECT * FROM roles")
            .fetch_all(&self.db)
            .await?;
        let by_id: HashMap<Uuid, Role> = all_roles.into_iter().map(|r| (r.id, r)).collect();

        // Use a Vec for the result so insertion order is preserved. The Java
        // side uses a `LinkedHashSet` for the same reason.
        let mut effective: Vec<String> = Vec::new();
        let mut visited: HashSet<Uuid> = HashSet::new();
        for r in direct {
            walk_ancestors(&r, &by_id, &mut effective, &mut visited);
        }
        Ok(effective)
    }

    pub async fn is_assigned(&self, user_id: Uuid, role_id: Uuid) -> sqlx::Result<bool> {
        let (count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM user_roles WHERE user_id = $1 AND role_id = $2",
        )
        .bind(user_id)
        .bind(role_id)
        .fetch_one(&self.db)
        .await?;
        Ok(count > 0)
    }

    pub async fn persist(&self, role: &Role) -> sqlx::Result<()> {
        sqlx::query(
            r#"INSERT INTO roles (id, name, description, parent_id, created_at)
               VALUES ($1, $2, $3, $4, $5)"#,
        )
        .bind(role.id)
        .bind(&role.name)
        .bind(&role.description)
        .bind(role.parent_id)
        .bind(role.created_at)
        .execute(&self.db)
        .await
        .map(|_| ())
    }

    pub async fn assign_to_user(&self, user_id: Uuid, role_id: Uuid) -> sqlx::Result<()> {
        sqlx::query(
            r#"INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)
               ON CONFLICT DO NOTHING"#,
        )
        .bind(user_id)
        .bind(role_id)
        .execute(&self.db)
        .await
        .map(|_| ())
    }

    pub async fn unassign_from_user(&self, user_id: Uuid, role_id: Uuid) -> sqlx::Result<u64> {
        let res = sqlx::query("DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2")
            .bind(user_id)
            .bind(role_id)
            .execute(&self.db)
            .await?;
        Ok(res.rows_affected())
    }

    /// Re-parent a role, guarding against cycles. Runs inside a transaction
    /// with `SELECT ... FOR UPDATE` on the full roles set — two concurrent
    /// callers can't both observe a cycle-free graph and then commit
    /// conflicting edges. Mirrors Java's `setParent` semantics exactly.
    pub async fn set_parent(
        &self,
        child_id: Uuid,
        parent_id: Option<Uuid>,
    ) -> Result<(), RoleError> {
        if let Some(p) = parent_id {
            if p == child_id {
                return Err(RoleError::Cycle(
                    "role cannot be its own parent".to_string(),
                ));
            }
        }

        let mut tx = self.db.begin().await?;

        if let Some(new_parent) = parent_id {
            let all: Vec<(Uuid, Option<Uuid>)> =
                sqlx::query_as("SELECT id, parent_id FROM roles FOR UPDATE")
                    .fetch_all(&mut *tx)
                    .await?;
            let parent_of: HashMap<Uuid, Option<Uuid>> = all.into_iter().collect();

            let mut cursor: Option<Uuid> = Some(new_parent);
            let mut seen: HashSet<Uuid> = HashSet::new();
            while let Some(c) = cursor {
                if c == child_id || !seen.insert(c) {
                    return Err(RoleError::Cycle("cycle detected in role hierarchy".into()));
                }
                cursor = parent_of.get(&c).copied().flatten();
            }
        }

        sqlx::query("UPDATE roles SET parent_id = $1 WHERE id = $2")
            .bind(parent_id)
            .bind(child_id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(())
    }
}

fn walk_ancestors(
    role: &Role,
    all: &HashMap<Uuid, Role>,
    sink: &mut Vec<String>,
    visited: &mut HashSet<Uuid>,
) {
    if !visited.insert(role.id) {
        return;
    }
    if !sink.iter().any(|n| n == &role.name) {
        sink.push(role.name.clone());
    }
    if let Some(parent_id) = role.parent_id {
        if let Some(parent) = all.get(&parent_id) {
            walk_ancestors(parent, all, sink, visited);
        }
    }
}
