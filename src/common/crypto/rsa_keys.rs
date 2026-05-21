//! Port of `com.xerika.auth.common.crypto.RsaKeyProvider`.
//!
//! Owns the RSA key set used to sign JWTs. Layout on disk:
//!
//! ```text
//! <dir>/<kid>.private.pem     # PKCS#8 PEM
//! <dir>/<kid>.public.pem      # X.509 SubjectPublicKeyInfo PEM
//! <dir>/active.kid            # ASCII kid of the currently-active key
//! ```
//!
//! `<kid>` is the **first 16 chars of base64url(SHA-256(public_key_x509_der))**
//! — identical to Java's `computeKid()`. Legacy `private.pem` / `public.pem`
//! from very early dev runs are migrated into the new naming scheme.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use anyhow::{Context, Result, anyhow};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{DecodingKey, EncodingKey};
use rand::rngs::OsRng;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::traits::PublicKeyParts;
use rsa::{BigUint, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};

const ACTIVE_KID_FILE: &str = "active.kid";
const RSA_BITS: usize = 2048;

#[derive(Clone)]
pub struct PublicKeyEntry {
    pub kid: String,
    pub public: RsaPublicKey,
    pub public_pem: String,
    pub decoding_key: DecodingKey,
}

struct KeyPair {
    private: RsaPrivateKey,
    public: RsaPublicKey,
    public_pem: String,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

struct Store {
    by_kid: BTreeMap<String, KeyPair>,
    active_kid: String,
}

pub struct RsaKeyProvider {
    keys_dir: PathBuf,
    inner: RwLock<Store>,
}

impl RsaKeyProvider {
    /// `keys_dir_cfg` mirrors the `auth.jwt.keys.dir` Quarkus config knob:
    /// if blank/`None`, falls back to `$HOME/.xerika/auth/keys`.
    pub fn init(keys_dir_cfg: Option<&str>) -> Result<Self> {
        let dir = match keys_dir_cfg {
            Some(s) if !s.trim().is_empty() => PathBuf::from(s.trim()),
            _ => user_home()
                .ok_or_else(|| anyhow!("cannot determine user home (HOME/USERPROFILE unset)"))?
                .join(".xerika")
                .join("auth")
                .join("keys"),
        };

        fs::create_dir_all(&dir).with_context(|| format!("create keys dir {}", dir.display()))?;

        let mut by_kid: BTreeMap<String, KeyPair> = BTreeMap::new();
        load_existing_keys(&dir, &mut by_kid)?;

        let active_kid_file = dir.join(ACTIVE_KID_FILE);
        let mut active_kid: Option<String> = None;
        if active_kid_file.exists() {
            let stored = fs::read_to_string(&active_kid_file)?.trim().to_string();
            if by_kid.contains_key(&stored) {
                active_kid = Some(stored);
            }
        }

        if active_kid.is_none() {
            // Legacy migration: very early dev runs wrote `private.pem`/`public.pem`
            // without a kid. Migrate the pair into the new naming scheme.
            let legacy_priv = dir.join("private.pem");
            let legacy_pub = dir.join("public.pem");
            if by_kid.is_empty() && legacy_priv.exists() && legacy_pub.exists() {
                let priv_pem = fs::read_to_string(&legacy_priv)?;
                let pub_pem = fs::read_to_string(&legacy_pub)?;
                let private = RsaPrivateKey::from_pkcs8_pem(&priv_pem)
                    .context("parse legacy private.pem")?;
                let public = RsaPublicKey::from_public_key_pem(&pub_pem)
                    .context("parse legacy public.pem")?;
                let kid = compute_kid(&public)?;
                write_key_files(&dir, &kid, &private, &public)?;
                let pair = KeyPair::build(private, public)?;
                by_kid.insert(kid.clone(), pair);
                let _ = fs::remove_file(&legacy_priv);
                let _ = fs::remove_file(&legacy_pub);
                tracing::info!(%kid, "migrated legacy keypair to kid-scheme");
            }

            if by_kid.is_empty() {
                let (private, public) = generate_keypair()?;
                let kid = compute_kid(&public)?;
                write_key_files(&dir, &kid, &private, &public)?;
                let pair = KeyPair::build(private, public)?;
                by_kid.insert(kid.clone(), pair);
                tracing::info!(%kid, "generated initial RSA keypair");
            }

            // First entry by BTreeMap iteration (alphabetical) becomes active.
            // Matches Java's `keysByKid.keySet().iterator().next()` semantics
            // — neither side promises a particular order, the JWKS lookup just
            // needs *some* key to start with.
            let first = by_kid
                .keys()
                .next()
                .cloned()
                .ok_or_else(|| anyhow!("key set unexpectedly empty"))?;
            fs::write(&active_kid_file, &first).context("write active.kid")?;
            active_kid = Some(first);
        }

        let active = active_kid.expect("active_kid set above");
        tracing::info!(total = by_kid.len(), active = %active, "RSA key set loaded");

        Ok(Self {
            keys_dir: dir,
            inner: RwLock::new(Store {
                by_kid,
                active_kid: active,
            }),
        })
    }

    /// Active key id — the `kid` JWS header value attached to newly-minted tokens.
    pub fn key_id(&self) -> String {
        self.inner.read().unwrap().active_kid.clone()
    }

    /// Encoding key for the active kid (for [`jsonwebtoken::encode`]).
    pub fn active_encoding_key(&self) -> (String, EncodingKey) {
        let store = self.inner.read().unwrap();
        let active = store.active_kid.clone();
        let pair = store
            .by_kid
            .get(&active)
            .expect("active kid must point at a loaded pair");
        (active, pair.encoding_key.clone())
    }

    /// Decoding key for a specific `kid`. Falls back to the active key if `kid`
    /// is unknown — matches `publicKeyByKid(kid).orElse(publicKey())`.
    pub fn decoding_key_by_kid(&self, kid: Option<&str>) -> DecodingKey {
        let store = self.inner.read().unwrap();
        if let Some(k) = kid {
            if let Some(pair) = store.by_kid.get(k) {
                return pair.decoding_key.clone();
            }
        }
        store
            .by_kid
            .get(&store.active_kid)
            .expect("active kid must be loaded")
            .decoding_key
            .clone()
    }

    /// All known public keys, suitable for JWKS publication. Result includes
    /// kid + RSA `n`/`e` components ready to serialize as a JWK.
    pub fn all_public_keys(&self) -> Vec<PublicKeyEntry> {
        let store = self.inner.read().unwrap();
        store
            .by_kid
            .iter()
            .map(|(kid, pair)| PublicKeyEntry {
                kid: kid.clone(),
                public: pair.public.clone(),
                public_pem: pair.public_pem.clone(),
                decoding_key: pair.decoding_key.clone(),
            })
            .collect()
    }

    /// Generate + persist a fresh keypair and flip the active marker over.
    /// Returns the new kid.
    pub fn rotate(&self) -> Result<String> {
        let (private, public) = generate_keypair()?;
        let kid = compute_kid(&public)?;
        write_key_files(&self.keys_dir, &kid, &private, &public)?;
        let pair = KeyPair::build(private, public)?;

        let mut store = self.inner.write().unwrap();
        store.by_kid.insert(kid.clone(), pair);
        store.active_kid = kid.clone();
        fs::write(self.keys_dir.join(ACTIVE_KID_FILE), &kid)
            .context("write active.kid (rotate)")?;
        tracing::info!(%kid, "rotated active signing key");
        Ok(kid)
    }

    /// RSA modulus `n` & exponent `e` for a kid, encoded as base64url
    /// (no padding) — the shape JWKS publication expects.
    pub fn jwk_modulus_exponent(&self, kid: &str) -> Option<(String, String)> {
        let store = self.inner.read().unwrap();
        let pair = store.by_kid.get(kid)?;
        Some((
            URL_SAFE_NO_PAD.encode(strip_leading_zero(&pair.public.n().to_bytes_be())),
            URL_SAFE_NO_PAD.encode(strip_leading_zero(&pair.public.e().to_bytes_be())),
        ))
    }
}

impl KeyPair {
    fn build(private: RsaPrivateKey, public: RsaPublicKey) -> Result<Self> {
        let public_pem = public
            .to_public_key_pem(LineEnding::LF)
            .context("encode public PEM")?;
        let private_pem = private
            .to_pkcs8_pem(LineEnding::LF)
            .context("encode private PEM")?
            .to_string();
        let encoding_key = EncodingKey::from_rsa_pem(private_pem.as_bytes())
            .context("jsonwebtoken EncodingKey")?;
        let decoding_key = DecodingKey::from_rsa_pem(public_pem.as_bytes())
            .context("jsonwebtoken DecodingKey")?;
        Ok(Self {
            private,
            public,
            public_pem,
            encoding_key,
            decoding_key,
        })
    }
}

fn generate_keypair() -> Result<(RsaPrivateKey, RsaPublicKey)> {
    let mut rng = OsRng;
    let private = RsaPrivateKey::new(&mut rng, RSA_BITS).context("RSA keygen")?;
    let public = RsaPublicKey::from(&private);
    Ok((private, public))
}

fn load_existing_keys(dir: &Path, into: &mut BTreeMap<String, KeyPair>) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = match entry.file_name().into_string() {
            Ok(s) => s,
            Err(_) => continue,
        };
        let Some(kid) = name.strip_suffix(".private.pem") else {
            continue;
        };
        let priv_path = entry.path();
        let pub_path = dir.join(format!("{kid}.public.pem"));
        if !pub_path.exists() {
            continue;
        }
        let priv_pem = fs::read_to_string(&priv_path)?;
        let pub_pem = fs::read_to_string(&pub_path)?;
        let private = RsaPrivateKey::from_pkcs8_pem(&priv_pem)
            .with_context(|| format!("parse {}", priv_path.display()))?;
        let public = RsaPublicKey::from_public_key_pem(&pub_pem)
            .with_context(|| format!("parse {}", pub_path.display()))?;
        into.insert(kid.to_string(), KeyPair::build(private, public)?);
    }
    Ok(())
}

fn write_key_files(
    dir: &Path,
    kid: &str,
    private: &RsaPrivateKey,
    public: &RsaPublicKey,
) -> Result<()> {
    let priv_pem = private
        .to_pkcs8_pem(LineEnding::LF)
        .context("encode private PEM")?;
    let pub_pem = public
        .to_public_key_pem(LineEnding::LF)
        .context("encode public PEM")?;

    write_atomic(&dir.join(format!("{kid}.private.pem")), priv_pem.as_bytes(), true)?;
    write_atomic(&dir.join(format!("{kid}.public.pem")), pub_pem.as_bytes(), false)?;
    Ok(())
}

/// Write to `<path>.tmp`, fsync-rename to `<path>`. Mirrors Java's
/// `Files.move(tmp, path, ATOMIC_MOVE, REPLACE_EXISTING)` — a crash mid-write
/// can't leave a half-written PEM that would block startup. On POSIX, private
/// keys get tightened to `0o600`.
fn write_atomic(path: &Path, bytes: &[u8], owner_only: bool) -> Result<()> {
    let tmp = path.with_extension(format!(
        "{}.tmp",
        path.extension().and_then(|e| e.to_str()).unwrap_or("")
    ));
    fs::write(&tmp, bytes)?;

    #[cfg(unix)]
    {
        if owner_only {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o600);
            fs::set_permissions(&tmp, perms)?;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = owner_only; // Windows ACLs — accept umask default (learning project).
    }

    fs::rename(&tmp, path)?;
    Ok(())
}

fn compute_kid(public: &RsaPublicKey) -> Result<String> {
    let der = public.to_public_key_der().context("encode public DER")?;
    let hash = Sha256::digest(der.as_bytes());
    let full = URL_SAFE_NO_PAD.encode(hash);
    // Match Java's `substring(0, 16)`.
    Ok(full[..16].to_string())
}

/// JWK encoding wants the big-endian unsigned representation of `n` and `e`.
/// `BigUint::to_bytes_be` already produces unsigned bytes (no sign byte), so
/// the only thing we need to guard is the rare case of a leading 0x00 padding
/// — strip it so the JWK is byte-exact across implementations.
fn strip_leading_zero(bytes: &[u8]) -> &[u8] {
    if bytes.first() == Some(&0) && bytes.len() > 1 {
        &bytes[1..]
    } else {
        bytes
    }
}

fn user_home() -> Option<PathBuf> {
    for var in ["HOME", "USERPROFILE"] {
        if let Ok(val) = env::var(var) {
            if !val.is_empty() {
                return Some(PathBuf::from(val));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bootstraps a provider in a temp dir, then loads a second one and
    /// confirms the kid + active marker round-trip cleanly across restarts.
    #[test]
    fn bootstrap_then_reload_preserves_active_kid() {
        let tmp = std::env::temp_dir().join(format!(
            "auth-server-test-{}",
            uuid::Uuid::new_v4()
        ));
        let cfg = tmp.to_string_lossy().to_string();

        let p1 = RsaKeyProvider::init(Some(&cfg)).expect("init#1");
        let kid1 = p1.key_id();

        let p2 = RsaKeyProvider::init(Some(&cfg)).expect("init#2");
        assert_eq!(p2.key_id(), kid1);

        // sanity: encoding key exists, JWK n/e are non-empty.
        let (kid_e, _ek) = p2.active_encoding_key();
        assert_eq!(kid_e, kid1);
        let (n, e) = p2.jwk_modulus_exponent(&kid1).expect("jwk n/e");
        assert!(!n.is_empty());
        assert!(!e.is_empty());

        let _ = fs::remove_dir_all(&tmp);
    }
}

// Silence dead-code on PublicKeyEntry.public / BigUint import while Phase 7 (JWKS)
// hasn't landed yet.
#[allow(dead_code)]
fn _ensure_pub_used(p: &PublicKeyEntry) -> usize {
    let _ = BigUint::from(1u32);
    p.public.size()
}
