//! Redis key namespace constants — byte-identical to `RedisKeys.java`. Keep
//! the prefixes in sync if you ever rename one; both servers index the same
//! Redis instance during cutover.

pub fn auth_code(code: &str) -> String {
    format!("authcode:{code}")
}

pub fn device_by_code(device_code: &str) -> String {
    format!("device:dc:{device_code}")
}

pub fn device_by_user_code(user_code: &str) -> String {
    format!("device:uc:{user_code}")
}

pub fn pending_auth(state: &str) -> String {
    format!("pending:{state}")
}

pub fn session(token_hash: &str) -> String {
    format!("session:{token_hash}")
}

pub fn client(client_id: &str) -> String {
    format!("client:{client_id}")
}

pub fn rl_login_email(email: &str) -> String {
    format!("rl:login:email:{email}")
}

pub fn rl_login_ip(ip: &str) -> String {
    format!("rl:login:ip:{ip}")
}

pub fn rl_signup_ip(ip: &str) -> String {
    format!("rl:signup:ip:{ip}")
}

pub fn rl_verify_email(email: &str) -> String {
    format!("rl:verify-email:{email}")
}

pub fn rl_device_auth(client_id: &str) -> String {
    format!("rl:device-auth:{client_id}")
}
