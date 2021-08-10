//! JWK and JWK Set.
use std::collections::HashMap;

use crate::{
    es256::ES256PublicKey, rs256::RS256PublicKey, url_safe_trailing_bits, verify, verify_only,
    Error, Header, HeaderAndClaims, Result, VerificationKey,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

pub trait PublicKeyToJwk: VerificationKey {
    fn to_jwk(&self) -> Result<Jwk>;
}

/// JWK Representation.
#[non_exhaustive]
#[derive(Debug, Deserialize, Serialize, Default)]
pub struct Jwk {
    pub kty: String,
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub key_ops: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
}

impl Jwk {
    pub fn to_verification_key(&self) -> Result<Box<dyn VerificationKey>> {
        // Check `use` and `key_ops`.
        if !matches!(self.use_.as_deref(), None | Some("sig")) {
            return Err(Error::UnsupportedOrInvalidKey);
        }
        if !(self.key_ops.is_empty() || self.key_ops.iter().any(|ops| ops == "verify")) {
            return Err(Error::UnsupportedOrInvalidKey);
        }

        // If let would be too long.
        #[allow(clippy::single_match)]
        match &*self.kty {
            "RSA" => match (self.alg.as_deref(), &self.n, &self.e) {
                (None | Some("RS256"), Some(ref n), Some(ref e)) => {
                    let n = base64::decode_config(n, url_safe_trailing_bits())?;
                    let e = base64::decode_config(e, url_safe_trailing_bits())?;
                    return Ok(Box::new(RS256PublicKey::from_components(&n, &e)?));
                }
                _ => {}
            },
            "EC" => match (self.alg.as_deref(), self.crv.as_deref(), &self.x, &self.y) {
                (None | Some("ES256"), None | Some("P-256"), Some(ref x), Some(ref y)) => {
                    let x = base64::decode_config(x, url_safe_trailing_bits())?;
                    let y = base64::decode_config(y, url_safe_trailing_bits())?;
                    return Ok(Box::new(ES256PublicKey::from_coordinates(&x, &y)?));
                }
                _ => {}
            },
            _ => {}
        }

        Err(Error::UnsupportedOrInvalidKey)
    }
}

/// JWK Set Representation.
#[derive(Debug, Serialize, Deserialize)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}

impl JwkSet {
    pub fn verifier(&self) -> JwkSetVerifier {
        let mut prepared = JwkSetVerifier {
            keys: HashMap::new(),
        };
        for k in self.keys.iter() {
            if let Some(ref kid) = k.kid {
                if let Ok(vk) = k.to_verification_key() {
                    prepared.keys.insert(kid.clone(), vk);
                }
            }
        }
        prepared
    }
}

/// Jwk set parsed and converted, ready to verify tokens.
pub struct JwkSetVerifier {
    keys: HashMap<String, Box<dyn VerificationKey>>,
}

impl JwkSetVerifier {
    pub fn find(&self, kid: &str) -> Option<&dyn VerificationKey> {
        if let Some(vk) = self.keys.get(kid) {
            Some(&**vk)
        } else {
            None
        }
    }

    /// Decode and verify token with keys from this JWK set.
    ///
    /// The `alg`, `exp` and `nbf` fields are automatically checked.
    pub fn verify<ExtraClaims: DeserializeOwned>(
        &self,
        token: &str,
    ) -> Result<HeaderAndClaims<ExtraClaims>> {
        let mut parts = token.split('.');

        let mut header = parts.next().ok_or(Error::InvalidToken)?.as_bytes();

        let header_r = base64::read::DecoderReader::new(&mut header, url_safe_trailing_bits());
        let header: Header = serde_json::from_reader(header_r)?;

        let kid = header.kid.as_deref().ok_or(Error::NoKid)?;
        let k = self.find(kid).ok_or(Error::NoKey)?;

        verify(token, k)
    }

    /// Decode and verify token with keys from this JWK set. Won't check `exp` and `nbf`.
    pub fn verify_only<ExtraClaims: DeserializeOwned>(
        &self,
        token: &str,
    ) -> Result<HeaderAndClaims<ExtraClaims>> {
        let mut parts = token.split('.');

        let mut header = parts.next().ok_or(Error::InvalidToken)?.as_bytes();

        let header_r = base64::read::DecoderReader::new(&mut header, url_safe_trailing_bits());
        let header: Header = serde_json::from_reader(header_r)?;

        let kid = header.kid.as_deref().ok_or(Error::NoKid)?;
        let k = self.find(kid).ok_or(Error::NoKey)?;

        verify_only(token, k)
    }
}

#[cfg(feature = "remote-jwks")]
struct JWKSCache {
    jwks: JwkSetVerifier,
    valid_until: std::time::Instant,
}

/// A JWK Set served from a remote url. Automatically fetched and cached.
#[cfg(feature = "remote-jwks")]
pub struct RemoteJwksVerifier {
    url: String,
    client: reqwest::Client,
    cache_duration: std::time::Duration,
    cache: tokio::sync::RwLock<Option<JWKSCache>>,
}

#[cfg(feature = "remote-jwks")]
impl RemoteJwksVerifier {
    pub fn new(
        url: String,
        client: Option<reqwest::Client>,
        cache_duration: std::time::Duration,
    ) -> Self {
        Self {
            url,
            client: client.unwrap_or_default(),
            cache_duration,
            cache: tokio::sync::RwLock::new(None),
        }
    }

    async fn get_verifier(&self) -> Result<tokio::sync::RwLockReadGuard<'_, JwkSetVerifier>> {
        let cache = self.cache.read().await;
        // Cache still valid.
        if let Some(c) = &*cache {
            if c.valid_until
                .checked_duration_since(std::time::Instant::now())
                .is_some()
            {
                return Ok(tokio::sync::RwLockReadGuard::map(cache, |c| {
                    &c.as_ref().unwrap().jwks
                }));
            }
        }
        drop(cache);

        let mut cache = self.cache.write().await;
        if let Some(c) = &*cache {
            if c.valid_until
                .checked_duration_since(std::time::Instant::now())
                .is_some()
            {
                return Ok(tokio::sync::RwLockReadGuard::map(cache.downgrade(), |c| {
                    &c.as_ref().unwrap().jwks
                }));
            }
        }
        let response = self
            .client
            .get(&self.url)
            .header("accept", "application/json")
            .send()
            .await?;
        let jwks: JwkSet = response.json().await?;

        *cache = Some(JWKSCache {
            jwks: jwks.verifier(),
            valid_until: std::time::Instant::now() + self.cache_duration,
        });

        Ok(tokio::sync::RwLockReadGuard::map(cache.downgrade(), |c| {
            &c.as_ref().unwrap().jwks
        }))
    }

    pub async fn verify<E: DeserializeOwned>(&self, token: &str) -> Result<HeaderAndClaims<E>> {
        let v = self.get_verifier().await?;
        v.verify(token)
    }

    pub async fn verify_only<E: DeserializeOwned>(
        &self,
        token: &str,
    ) -> Result<HeaderAndClaims<E>> {
        let v = self.get_verifier().await?;
        v.verify_only(token)
    }
}

#[cfg(test)]
mod tests {
    use crate::{es256::ES256PrivateKey, sign};

    use super::*;

    #[test]
    fn test_jwk() -> Result<()> {
        assert!(Jwk {
            kty: "RSA".to_string(),
            use_: Some("enc".into()),
            ..Default::default()
        }
        .to_verification_key()
        .is_err());
        assert!(Jwk {
            kty: "RSA".to_string(),
            key_ops: vec!["encryption".into()],
            ..Default::default()
        }
        .to_verification_key()
        .is_err());
        Ok(())
    }

    #[derive(Serialize, Deserialize)]
    struct MyClaim {
        foo: String,
    }

    #[test]
    fn test_jwks_verify() -> Result<()> {
        let k = ES256PrivateKey::generate()?;
        let mut k_jwk = k.to_jwk()?;
        k_jwk.kid = Some("my key".into());
        let jwks = JwkSet { keys: vec![k_jwk] };
        let verifier = jwks.verifier();

        let token = sign(
            HeaderAndClaims::with_claims(MyClaim { foo: "bar".into() }).set_kid("my key"),
            &k,
        )?;

        verifier.verify_only::<MyClaim>(&token)?;
        let verified = verifier.verify::<MyClaim>(&token)?;
        assert_eq!(verified.claims.extra.foo, "bar");

        Ok(())
    }
}
