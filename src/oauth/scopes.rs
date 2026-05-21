//! Port of `com.xerika.auth.oauth.Scopes`.
//!
//! Scopes are stored on the client row as a space-or-comma-separated string.
//! `parse` normalises into a set, `is_subset_of` checks that the requested
//! set is contained in the allowed set — used both at `/authorize` (drop
//! requests asking for unregistered scopes) and at `/token` (client_credentials
//! re-check).

use std::collections::HashSet;

pub fn parse(raw: Option<&str>) -> HashSet<String> {
    let Some(s) = raw else {
        return HashSet::new();
    };
    if s.trim().is_empty() {
        return HashSet::new();
    }
    s.split(|c: char| c.is_whitespace() || c == ',')
        .map(|t| t.trim())
        .filter(|t| !t.is_empty())
        .map(|t| t.to_string())
        .collect()
}

pub fn is_subset_of(requested: Option<&str>, allowed: Option<&str>) -> bool {
    let req_str = requested.map(str::trim).unwrap_or("");
    if req_str.is_empty() {
        return true;
    }
    let allow_str = allowed.map(str::trim).unwrap_or("");
    if allow_str.is_empty() {
        return false;
    }
    let allowed_set = parse(Some(allow_str));
    parse(Some(req_str)).iter().all(|s| allowed_set.contains(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_space_and_comma_separated() {
        let s = parse(Some("openid profile,email"));
        assert!(s.contains("openid"));
        assert!(s.contains("profile"));
        assert!(s.contains("email"));
    }

    #[test]
    fn subset_passes_when_all_requested_are_allowed() {
        assert!(is_subset_of(Some("openid email"), Some("openid email profile")));
    }

    #[test]
    fn subset_fails_when_extra_scope_requested() {
        assert!(!is_subset_of(Some("openid admin"), Some("openid email")));
    }

    #[test]
    fn empty_requested_is_always_subset() {
        assert!(is_subset_of(None, Some("openid")));
        assert!(is_subset_of(Some(""), Some("openid")));
    }

    #[test]
    fn empty_allowed_means_no_scopes_are_allowed() {
        assert!(!is_subset_of(Some("openid"), None));
        assert!(!is_subset_of(Some("openid"), Some("")));
    }
}
