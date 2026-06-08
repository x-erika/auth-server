//! Port of `com.xerika.auth.login.LoginService`.
//!
//! Authenticates by username **or** email + password (Argon2id). Carries the
//! same timing-equalizer trick as the Java side: a `DUMMY_HASH` computed
//! once at process start so failed lookups still incur the full ~50ms
//! Argon2 work-factor — closes the response-timing oracle that would
//! otherwise leak "this account exists vs. doesn't".

use once_cell::sync::Lazy;

use crate::common::crypto::argon2 as argon2_hasher;
use crate::common::crypto::argon2::Hashed;
use crate::user::{CredentialRepository, User, UserRepository};

static DUMMY_HASH: Lazy<Hashed> =
    Lazy::new(|| argon2_hasher::hash("dummy-not-a-real-password-timing-equalizer"));

#[derive(Clone)]
pub struct LoginService {
    users: UserRepository,
    credentials: CredentialRepository,
}

impl LoginService {
    pub fn new(users: UserRepository, credentials: CredentialRepository) -> Self {
        Self { users, credentials }
    }

    /// Authenticate by email or username. If the identifier contains an `@`
    /// we go straight to the email lookup; otherwise try username first,
    /// then fall back to email. Matches Java order-of-resolution exactly.
    pub async fn authenticate(
        &self,
        identifier: Option<&str>,
        raw_password: Option<&str>,
    ) -> sqlx::Result<Option<User>> {
        let identifier = match identifier.map(str::trim) {
            Some(s) if !s.is_empty() => s,
            _ => return Ok(None),
        };
        let raw_password = match raw_password {
            Some(p) if !p.is_empty() => p,
            _ => return Ok(None),
        };

        let user: Option<User> = if identifier.contains('@') {
            self.users.find_by_email(identifier).await?
        } else {
            match self.users.find_by_username(identifier).await? {
                Some(u) => Some(u),
                None => self.users.find_by_email(identifier).await?,
            }
        };

        let credential = match &user {
            Some(u) => {
                self.credentials
                    .find_first_by_user_id_and_type(u.id, "password")
                    .await?
            }
            None => None,
        };

        // Pull the (secret_data, credential_data) pair from the credential
        // OR from the dummy hash if either is missing. The verify call
        // always runs so timing stays constant.
        let (secret_data, credential_data) = match &credential {
            Some(c) => (
                c.secret_data.clone().unwrap_or_default(),
                c.credential_data.clone().unwrap_or_default(),
            ),
            None => (
                DUMMY_HASH.secret_data.clone(),
                DUMMY_HASH.credential_data.clone(),
            ),
        };

        let ok = argon2_hasher::verify_async(raw_password, &secret_data, &credential_data).await;

        let user = user.filter(|u| u.enabled && u.email_verified);
        if user.is_none() || credential.is_none() || !ok {
            return Ok(None);
        }
        Ok(user)
    }
}
