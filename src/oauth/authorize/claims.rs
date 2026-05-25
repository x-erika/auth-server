//! Port of `com.xerika.auth.oauth.authorize.ClaimsRequest`.
//!
//! Parses OIDC `claims` parameter (`{"id_token": {...}, "userinfo": {...}}`)
//! and exposes the field-name sets the token issuer consults to decide
//! which claims to include beyond the defaults.

use std::collections::HashSet;

use serde_json::Value;

#[derive(Debug, Clone, Default)]
pub struct ClaimsRequest {
    id_token_claims: HashSet<String>,
    userinfo_claims: HashSet<String>,
}

impl ClaimsRequest {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn parse(json: Option<&str>) -> Self {
        let Some(s) = json else {
            return Self::empty();
        };
        if s.trim().is_empty() {
            return Self::empty();
        }
        let node: Value = match serde_json::from_str(s) {
            Ok(v) => v,
            Err(_) => return Self::empty(),
        };
        Self {
            id_token_claims: collect_field_names(&node, "id_token"),
            userinfo_claims: collect_field_names(&node, "userinfo"),
        }
    }

    pub fn id_token_claims(&self) -> &HashSet<String> {
        &self.id_token_claims
    }

    pub fn userinfo_claims(&self) -> &HashSet<String> {
        &self.userinfo_claims
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.id_token_claims.is_empty() && self.userinfo_claims.is_empty()
    }
}

fn collect_field_names(root: &Value, section: &str) -> HashSet<String> {
    let mut names = HashSet::new();
    let Some(obj) = root.get(section).and_then(|v| v.as_object()) else {
        return names;
    };
    for k in obj.keys() {
        names.insert(k.clone());
    }
    names
}
