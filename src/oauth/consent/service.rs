//! Port of `ConsentService.java`.

use chrono::Utc;
use uuid::Uuid;

use crate::oauth::scopes;

use super::model::UserConsent;
use super::repository::UserConsentRepository;

#[derive(Clone)]
pub struct ConsentService {
    repo: UserConsentRepository,
}

impl ConsentService {
    pub fn new(repo: UserConsentRepository) -> Self {
        Self { repo }
    }

    pub async fn has_consent(
        &self,
        user_id: Uuid,
        client_id: Uuid,
        requested_scope_raw: Option<&str>,
    ) -> sqlx::Result<bool> {
        let requested = scopes::parse(requested_scope_raw);
        if requested.is_empty() {
            return Ok(true);
        }
        let existing = self.repo.find(user_id, client_id).await?;
        let Some(existing) = existing else {
            return Ok(false);
        };
        let granted = scopes::parse(Some(&existing.scopes));
        Ok(requested.iter().all(|s| granted.contains(s)))
    }

    pub async fn grant(
        &self,
        user_id: Uuid,
        client_id: Uuid,
        requested_scope_raw: Option<&str>,
    ) -> sqlx::Result<()> {
        let requested = scopes::parse(requested_scope_raw);
        let now = Utc::now().naive_utc();
        let existing = self.repo.find(user_id, client_id).await?;
        match existing {
            None => {
                let mut sorted: Vec<&String> = requested.iter().collect();
                sorted.sort();
                let scopes_str = sorted
                    .into_iter()
                    .cloned()
                    .collect::<Vec<String>>()
                    .join(" ");
                let consent = UserConsent {
                    id: Uuid::new_v4(),
                    user_id,
                    client_id,
                    scopes: scopes_str,
                    granted_at: now,
                    updated_at: now,
                };
                self.repo.persist(&consent).await?;
            }
            Some(mut existing) => {
                // Union of existing and newly-requested scopes.
                let mut merged = scopes::parse(Some(&existing.scopes));
                for s in requested {
                    merged.insert(s);
                }
                let mut sorted: Vec<&String> = merged.iter().collect();
                sorted.sort();
                existing.scopes = sorted
                    .into_iter()
                    .cloned()
                    .collect::<Vec<String>>()
                    .join(" ");
                existing.updated_at = now;
                self.repo.update(&existing).await?;
            }
        }
        Ok(())
    }

    pub async fn revoke(&self, user_id: Uuid, client_id: Uuid) -> sqlx::Result<u64> {
        self.repo.revoke(user_id, client_id).await
    }
}
