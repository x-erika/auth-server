#[derive(Debug, Clone)]
pub struct LogoutResult {
    pub terminated: bool,
    pub frontchannel_logout_uris: Vec<String>,
    pub validated_post_logout_redirect_uri: Option<String>,
}

impl LogoutResult {
    pub fn none(validated_post_logout_redirect_uri: Option<String>) -> Self {
        Self {
            terminated: false,
            frontchannel_logout_uris: Vec::new(),
            validated_post_logout_redirect_uri,
        }
    }
}
