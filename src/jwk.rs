//! JWK and JWK Set.

#[cfg(feature = "openssl")]
use crate::{
    ecdsa::{EcdsaAlgorithm, EcdsaPrivateKey, EcdsaPublicKey},
    eddsa::{Ed25519PrivateKey, Ed25519PublicKey},
};
use crate::{
    rsa::RsaAlgorithm, some::SomePublicKey, verify, verify_only, Error, Header, HeaderAndClaims,
    PublicKeyToJwk, Result, SigningKey, SomePrivateKey, VerificationKey, URL_SAFE_TRAILING_BITS,
};
use base64::Engine as _;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub p: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub q: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dq: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qi: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub oth: Vec<Value>,
}

impl Jwk {
    pub fn to_verification_key(&self) -> Result<SomePublicKey> {
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
            #[cfg(any(feature = "rsa", feature = "openssl"))]
            "RSA" => return self.rsa_verification_key(),
            #[cfg(feature = "openssl")]
            "EC" => return self.ec_verification_key(),
            #[cfg(feature = "openssl")]
            "OKP" => return self.okp_verification_key(),
            _ => {}
        }

        Err(Error::UnsupportedOrInvalidKey)
    }

    pub fn to_signing_key(&self, rsa_fallback_algorithm: RsaAlgorithm) -> Result<SomePrivateKey> {
        match &*self.kty {
            #[cfg(any(feature = "rsa", feature = "openssl"))]
            "RSA" => self.rsa_signing_key(rsa_fallback_algorithm),
            #[cfg(feature = "openssl")]
            "EC" => self.ec_signing_key(),
            #[cfg(feature = "openssl")]
            "OKP" => self.okp_signing_key(),
            _ => {
                let _ = rsa_fallback_algorithm;
                Err(Error::UnsupportedOrInvalidKey)
            }
        }
    }

    #[cfg(any(feature = "rsa", feature = "openssl"))]
    #[allow(clippy::many_single_char_names)]
    pub(super) fn rsa_signing_key(
        &self,
        rsa_fallback_algorithm: RsaAlgorithm,
    ) -> Result<SomePrivateKey> {
        let alg = if let Some(ref alg) = self.alg {
            RsaAlgorithm::from_name(alg)?
        } else {
            rsa_fallback_algorithm
        };
        match (self.d.as_deref(), self.n.as_deref(), self.e.as_deref()) {
            (Some(d), Some(n), Some(e)) => {
                let d = URL_SAFE_TRAILING_BITS.decode(d)?;
                let n = URL_SAFE_TRAILING_BITS.decode(n)?;
                let e = URL_SAFE_TRAILING_BITS.decode(e)?;
                match (
                    self.p.as_deref(),
                    self.q.as_deref(),
                    self.dp.as_deref(),
                    self.dq.as_deref(),
                    self.qi.as_deref(),
                    self.oth.is_empty(),
                ) {
                    (None, None, None, None, None, true) => {
                        crate::rsa::RsaPrivateKey::from_components(&n, &e, &d, vec![], alg)
                            .map(Into::into)
                    }
                    (Some(p), Some(q), Some(_dp), Some(_dq), Some(_qi), true) => {
                        let p = URL_SAFE_TRAILING_BITS.decode(p)?;
                        let q = URL_SAFE_TRAILING_BITS.decode(q)?;
                        crate::rsa::RsaPrivateKey::from_components(&n, &e, &d, vec![p, q], alg)
                            .map(Into::into)
                    }
                    _ => Err(Error::UnsupportedOrInvalidKey),
                }
            }
            _ => Err(Error::UnsupportedOrInvalidKey),
        }
    }

    #[cfg(any(feature = "rsa", feature = "openssl"))]
    pub(super) fn rsa_verification_key(&self) -> Result<SomePublicKey> {
        match (self.alg.as_deref(), &self.n, &self.e) {
            (alg, Some(ref n), Some(ref e)) => {
                let n = URL_SAFE_TRAILING_BITS.decode(n)?;
                let e = URL_SAFE_TRAILING_BITS.decode(e)?;
                // If `alg` is specified, the key will only verify
                // signatures generated by ONLY this specific `alg`,
                // otherwise it will verify signatures generated by ANY RSA
                // algorithm.
                let alg = if let Some(alg) = alg {
                    Some(RsaAlgorithm::from_name(alg)?)
                } else {
                    None
                };
                Ok(SomePublicKey::Rsa(
                    crate::rsa::RsaPublicKey::from_components(&n, &e, alg)?,
                ))
            }
            _ => Err(Error::UnsupportedOrInvalidKey),
        }
    }

    #[cfg(feature = "openssl")]
    pub(super) fn ec_verification_key(&self) -> Result<SomePublicKey> {
        match (self.crv.as_deref(), &self.x, &self.y) {
            // For EC keys `crv` is required.
            (Some(crv), Some(ref x), Some(ref y)) => {
                let x = URL_SAFE_TRAILING_BITS.decode(x)?;
                let y = URL_SAFE_TRAILING_BITS.decode(y)?;
                let alg = EcdsaAlgorithm::from_curve_name(crv)?;
                Ok(SomePublicKey::Ecdsa(EcdsaPublicKey::from_coordinates(
                    &x, &y, alg,
                )?))
            }
            _ => Err(Error::UnsupportedOrInvalidKey),
        }
    }

    #[cfg(feature = "openssl")]
    pub(super) fn okp_verification_key(&self) -> Result<SomePublicKey> {
        match (self.crv.as_deref(), &self.x) {
            (Some("Ed25519"), Some(ref x)) => {
                let x = URL_SAFE_TRAILING_BITS.decode(x)?;
                Ok(SomePublicKey::Ed25519(Ed25519PublicKey::from_bytes(&x)?))
            }
            _ => Err(Error::UnsupportedOrInvalidKey),
        }
    }

    #[cfg(feature = "openssl")]
    pub(super) fn ec_signing_key(&self) -> Result<SomePrivateKey> {
        match (
            self.crv.as_deref(),
            self.d.as_deref(),
            self.x.as_deref(),
            self.y.as_deref(),
        ) {
            (Some(crv), Some(d), Some(x), Some(y)) => {
                let alg = EcdsaAlgorithm::from_curve_name(crv)?;
                let d = URL_SAFE_TRAILING_BITS.decode(d)?;
                let x = URL_SAFE_TRAILING_BITS.decode(x)?;
                let y = URL_SAFE_TRAILING_BITS.decode(y)?;
                EcdsaPrivateKey::from_private_components(alg, &d, &x, &y).map(Into::into)
            }
            _ => Err(Error::UnsupportedOrInvalidKey),
        }
    }

    #[cfg(feature = "openssl")]
    pub(super) fn okp_signing_key(&self) -> Result<SomePrivateKey> {
        match (self.crv.as_deref(), self.d.as_deref()) {
            (Some("Ed25519"), Some(d)) => {
                let d = URL_SAFE_TRAILING_BITS.decode(d)?;
                Ed25519PrivateKey::from_bytes(&d).map(Into::into)
            }
            _ => Err(Error::UnsupportedOrInvalidKey),
        }
    }

    /// Get key thumbprint (rfc 7638) with SHA-256.
    pub fn get_thumbprint_sha256(&self) -> Result<[u8; 32]> {
        let as_json = match &*self.kty {
            "RSA" => {
                let mut v = BTreeMap::new();
                v.insert(
                    "e",
                    self.e.as_deref().ok_or(Error::UnsupportedOrInvalidKey)?,
                );
                v.insert("kty", "RSA");
                v.insert(
                    "n",
                    self.n.as_deref().ok_or(Error::UnsupportedOrInvalidKey)?,
                );
                serde_json::to_string(&v)?
            }
            "EC" => {
                let mut v = BTreeMap::new();
                v.insert(
                    "crv",
                    self.crv.as_deref().ok_or(Error::UnsupportedOrInvalidKey)?,
                );
                v.insert("kty", "EC");
                v.insert(
                    "x",
                    self.x.as_deref().ok_or(Error::UnsupportedOrInvalidKey)?,
                );
                v.insert(
                    "y",
                    self.y.as_deref().ok_or(Error::UnsupportedOrInvalidKey)?,
                );
                serde_json::to_string(&v)?
            }
            "OKP" => {
                let mut v = BTreeMap::new();
                v.insert(
                    "crv",
                    self.crv.as_deref().ok_or(Error::UnsupportedOrInvalidKey)?,
                );
                v.insert("kty", "OKP");
                v.insert(
                    "x",
                    self.x.as_deref().ok_or(Error::UnsupportedOrInvalidKey)?,
                );
                serde_json::to_string(&v)?
            }
            _ => return Err(Error::UnsupportedOrInvalidKey),
        };
        let hash = Sha256::digest(as_json.as_bytes());
        let mut out = [0u8; 32];
        out.copy_from_slice(&hash[..]);
        Ok(out)
    }

    /// Get key thumbprint with SHA-256, base64url-encoded.
    pub fn get_thumbprint_sha256_base64(&self) -> Result<String> {
        Ok(URL_SAFE_TRAILING_BITS.encode(self.get_thumbprint_sha256()?))
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
            require_kid: true,
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
    keys: HashMap<String, SomePublicKey>,
    pub(crate) require_kid: bool,
}

impl JwkSetVerifier {
    /// If called with `false`, subsequent `verify` and `verify_only` calls will
    /// try all keys from the key set if a `kid` is not specified in the token.
    pub fn set_require_kid(&mut self, required: bool) {
        self.require_kid = required;
    }

    pub fn find(&self, kid: &str) -> Option<&SomePublicKey> {
        self.keys.get(kid)
    }

    /// Decode and verify token with keys from this JWK set.
    ///
    /// The `alg`, `exp` and `nbf` fields are automatically checked.
    pub fn verify<ExtraClaims: DeserializeOwned>(
        &self,
        token: &str,
    ) -> Result<HeaderAndClaims<ExtraClaims>> {
        self.find_and_verify(token, verify)
    }

    /// Decode and verify token with keys from this JWK set. Won't check `exp` and `nbf`.
    pub fn verify_only<ExtraClaims: DeserializeOwned>(
        &self,
        token: &str,
    ) -> Result<HeaderAndClaims<ExtraClaims>> {
        self.find_and_verify(token, verify_only)
    }

    fn find_and_verify<ExtraClaims: DeserializeOwned>(
        &self,
        token: &str,
        verifier: fn(&str, &dyn VerificationKey) -> Result<HeaderAndClaims<ExtraClaims>>,
    ) -> Result<HeaderAndClaims<ExtraClaims>> {
        let mut parts = token.split('.');

        let mut header = parts.next().ok_or(Error::InvalidToken)?.as_bytes();

        let header_r = base64::read::DecoderReader::new(&mut header, &URL_SAFE_TRAILING_BITS);
        let header: Header = serde_json::from_reader(header_r)?;

        if let Some(kid) = header.kid {
            let k = self.find(&kid).ok_or(Error::NoKey)?;
            verifier(token, k)
        } else if !self.require_kid {
            if let Some(res) = self
                .keys
                .values()
                .map(|key| verifier(token, key))
                .find_map(|res| res.ok())
            {
                Ok(res)
            } else {
                Err(Error::NoKey)
            }
        } else {
            Err(Error::NoKey)
        }
    }
}

/// A key associated with a key id (`kid`).
///
/// When the key is used for signing, `kid` is automatically set.
#[derive(Debug)]
pub struct WithKid<S> {
    kid: String,
    inner: S,
}

impl<S> WithKid<S> {
    pub fn new(kid: String, inner: S) -> Self {
        Self { kid, inner }
    }

    /// Use key thumbprint as key id.
    pub fn new_with_thumbprint_id(inner: S) -> Result<Self>
    where
        S: PublicKeyToJwk,
    {
        Ok(Self {
            kid: inner.public_key_to_jwk()?.get_thumbprint_sha256_base64()?,
            inner,
        })
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    pub fn set_kid(&mut self, kid: impl Into<String>) {
        self.kid = kid.into();
    }

    pub fn as_inner(&self) -> &S {
        &self.inner
    }

    pub fn into_inner(self) -> S {
        self.inner
    }

    pub fn as_inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }
}

impl<S: SigningKey> SigningKey for WithKid<S> {
    fn kid(&self) -> Option<&str> {
        Some(&self.kid)
    }

    fn sign(&self, v: &[u8]) -> Result<smallvec::SmallVec<[u8; 64]>> {
        self.inner.sign(v)
    }

    fn alg(&self) -> &'static str {
        self.inner.alg()
    }
}

impl<S: VerificationKey> VerificationKey for WithKid<S> {
    fn verify(&self, v: &[u8], sig: &[u8], alg: &str) -> Result<()> {
        self.inner.verify(v, sig, alg)
    }
}

impl<K: PublicKeyToJwk> PublicKeyToJwk for WithKid<K> {
    fn public_key_to_jwk(&self) -> Result<Jwk> {
        let mut jwk = self.inner.public_key_to_jwk()?;
        jwk.kid = Some(self.kid.clone());
        Ok(jwk)
    }
}

#[cfg(feature = "remote-jwks")]
struct JWKSCache {
    jwks: JwkSetVerifier,
    last_retrieved: std::time::Instant,
}

#[cfg(feature = "remote-jwks")]
impl JWKSCache {
    fn fresher_than(&self, age: std::time::Duration) -> bool {
        self.last_retrieved
            .checked_add(age)
            .and_then(|deadline| deadline.checked_duration_since(std::time::Instant::now()))
            .is_some()
    }
}

/// A JWK Set served from a remote url. Automatically fetched and cached.
#[cfg(feature = "remote-jwks")]
pub struct RemoteJwksVerifier {
    url: String,
    client: reqwest::Client,
    cache_duration: std::time::Duration,
    cooldown: std::time::Duration,
    cache: tokio::sync::RwLock<Option<JWKSCache>>,
    require_kid: bool,
}

#[cfg(feature = "remote-jwks")]
impl RemoteJwksVerifier {
    /// Construct a new RemoteJwksVerifier with default settings.
    pub fn new(url: String) -> Self {
        Self::builder(url).build()
    }

    /// Construct a customized RemoteJwksVerifier.
    pub fn builder(url: String) -> RemoteJwksVerifierBuilder {
        RemoteJwksVerifierBuilder {
            url,
            client: None,
            cache_duration: None,
            cooldown: None,
            require_kid: true,
        }
    }

    async fn get_cache(&self) -> Result<tokio::sync::RwLockReadGuard<'_, JWKSCache>> {
        let cache = self.cache.read().await;
        if let Some(c) = &*cache {
            if c.fresher_than(self.cache_duration) {
                return Ok(tokio::sync::RwLockReadGuard::map(cache, |c| {
                    c.as_ref().unwrap()
                }));
            }
        }
        drop(cache);

        let mut cache = self.cache.write().await;
        if let Some(c) = &*cache {
            if c.fresher_than(self.cache_duration) {
                return Ok(tokio::sync::RwLockReadGuard::map(cache.downgrade(), |c| {
                    c.as_ref().unwrap()
                }));
            }
        }
        self.reload_jwks(&mut cache).await?;

        Ok(tokio::sync::RwLockReadGuard::map(cache.downgrade(), |c| {
            c.as_ref().unwrap()
        }))
    }

    async fn reload_jwks(
        &self,
        cache: &mut tokio::sync::RwLockWriteGuard<'_, Option<JWKSCache>>,
    ) -> Result<()> {
        let response = self
            .client
            .get(&self.url)
            .header("accept", "application/json")
            .send()
            .await?;
        let jwks: JwkSet = response.json().await?;

        cache.replace(JWKSCache {
            jwks: {
                let mut v = jwks.verifier();
                v.require_kid = self.require_kid;
                v
            },
            last_retrieved: std::time::Instant::now(),
        });
        Ok(())
    }

    async fn verify_with_reload_on_no_key<E, F>(
        &self,
        token: &str,
        verify: F,
    ) -> Result<HeaderAndClaims<E>>
    where
        E: DeserializeOwned,
        F: Fn(&JwkSetVerifier, &str) -> Result<HeaderAndClaims<E>>,
    {
        let cache = self.get_cache().await?;
        match verify(&cache.jwks, token) {
            Ok(v) => Ok(v),
            err @ Err(Error::NoKey) => {
                if cache.fresher_than(self.cooldown) {
                    return err;
                }
                drop(cache);

                let mut cache = self.cache.write().await;
                if let Some(c) = cache.as_ref() {
                    if c.fresher_than(self.cooldown) {
                        return verify(&c.jwks, token);
                    }
                }
                self.reload_jwks(&mut cache).await?;
                match cache.as_ref() {
                    Some(c) => verify(&c.jwks, token),
                    None => Err(Error::NoKey),
                }
            }
            Err(e) => Err(e),
        }
    }

    pub async fn verify<E: DeserializeOwned>(&self, token: &str) -> Result<HeaderAndClaims<E>> {
        self.verify_with_reload_on_no_key(token, |jwks, token| jwks.verify(token))
            .await
    }

    pub async fn verify_only<E: DeserializeOwned>(
        &self,
        token: &str,
    ) -> Result<HeaderAndClaims<E>> {
        self.verify_with_reload_on_no_key(token, |jwks, token| jwks.verify_only(token))
            .await
    }
}

#[cfg(feature = "remote-jwks")]
pub struct RemoteJwksVerifierBuilder {
    url: String,
    client: Option<reqwest::Client>,
    cache_duration: Option<std::time::Duration>,
    cooldown: Option<std::time::Duration>,
    require_kid: bool,
}

#[cfg(feature = "remote-jwks")]
impl RemoteJwksVerifierBuilder {
    /// Provide an HTTP client for fetching the JWK set.
    pub fn with_client(mut self, client: reqwest::Client) -> Self {
        self.client = Some(client);
        self
    }

    /// Set how long the fetched JWK set should be cached. Default is
    /// 5 minutes.
    pub fn with_cache_duration(mut self, duration: std::time::Duration) -> Self {
        self.cache_duration = Some(duration);
        self
    }

    /// Set cooldown for reloading JWKs in response to unknown `kid`.
    /// Default is 30 seconds.
    pub fn with_cooldown(mut self, duration: std::time::Duration) -> Self {
        self.cooldown = Some(duration);
        self
    }

    /// Calls to `verify` and `verify_only` calls will try all keys
    /// from the key set if a `kid` is not specified in the token.
    pub fn with_kid_optional(mut self) -> Self {
        self.require_kid = false;
        self
    }

    /// Construct the RemoteJwksVerifier.
    pub fn build(self) -> RemoteJwksVerifier {
        RemoteJwksVerifier {
            url: self.url,
            client: self.client.unwrap_or_default(),
            cache_duration: self
                .cache_duration
                .unwrap_or_else(|| std::time::Duration::from_secs(300)),
            cooldown: self
                .cooldown
                .unwrap_or_else(|| std::time::Duration::from_secs(30)),
            cache: tokio::sync::RwLock::new(None),
            require_kid: self.require_kid,
        }
    }
}

#[cfg(test)]
mod tests {
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

    #[cfg(any(feature = "rsa", feature = "openssl"))]
    #[test]
    fn test_rsa_thumbprint() -> Result<()> {
        use crate::rsa::{RsaAlgorithm, RsaPrivateKey};
        RsaPrivateKey::generate(2048, RsaAlgorithm::RS256)?
            .public_key_to_jwk()?
            .get_thumbprint_sha256_base64()?;
        Ok(())
    }

    #[cfg(feature = "openssl")]
    #[test]
    fn test_ec_ed_thumbprint() -> Result<()> {
        use crate::{
            ecdsa::{EcdsaAlgorithm, EcdsaPrivateKey},
            eddsa::Ed25519PrivateKey,
        };
        EcdsaPrivateKey::generate(EcdsaAlgorithm::ES256)?
            .public_key_to_jwk()?
            .get_thumbprint_sha256_base64()?;
        Ed25519PrivateKey::generate()?
            .public_key_to_jwk()?
            .get_thumbprint_sha256_base64()?;
        Ok(())
    }

    #[cfg(any(feature = "rsa", feature = "openssl"))]
    #[derive(serde::Serialize, serde::Deserialize)]
    struct MyClaim {
        foo: String,
    }

    #[cfg(any(feature = "rsa", feature = "openssl"))]
    #[test]
    fn test_jwks_verify() -> Result<()> {
        use crate::{
            rsa::{RsaAlgorithm, RsaPrivateKey},
            sign,
        };

        let k = RsaPrivateKey::generate(2048, RsaAlgorithm::RS256)?;
        let kk = WithKid::new("my key".into(), k.clone());
        let k_jwk = kk.public_key_to_jwk()?;
        let jwks = JwkSet { keys: vec![k_jwk] };
        let mut verifier = jwks.verifier();

        // jwt with kid
        {
            let mut jwt = HeaderAndClaims::with_claims(MyClaim { foo: "bar".into() });
            jwt.set_kid("my key");
            let token = sign(&mut jwt, &k)?;

            verifier.verify_only::<MyClaim>(&token)?;
            let verified = verifier.verify::<MyClaim>(&token)?;
            assert_eq!(verified.claims.extra.foo, "bar");
        }

        // jwt with not exist kid
        {
            let mut jwt = HeaderAndClaims::with_claims(MyClaim { foo: "bar".into() });
            jwt.set_kid("my key2");
            let token = sign(&mut jwt, &k)?;

            let res = verifier.verify_only::<MyClaim>(&token);
            assert!(res.is_err());
        }

        // jwt with override kid
        {
            let mut jwt = HeaderAndClaims::with_claims(MyClaim { foo: "bar".into() });
            jwt.set_kid("my key2");
            let token = sign(&mut jwt, &kk)?;

            verifier.verify_only::<MyClaim>(&token)?;
            let verified = verifier.verify::<MyClaim>(&token)?;
            assert_eq!(verified.claims.extra.foo, "bar");
        }

        // jwt without kid
        {
            let token = sign(
                &mut HeaderAndClaims::with_claims(MyClaim { foo: "bar".into() }),
                &k,
            )?;

            let res = verifier.verify_only::<MyClaim>(&token);
            assert!(res.is_err());
        }

        // jwt without kid and verifier does not require one.
        {
            let token = sign(
                &mut HeaderAndClaims::with_claims(MyClaim { foo: "bar".into() }),
                &k,
            )?;

            verifier.set_require_kid(false);
            verifier.verify::<MyClaim>(&token)?;
            let verified = verifier.verify_only::<MyClaim>(&token)?;
            assert_eq!(verified.claims.extra.foo, "bar");
        }

        Ok(())
    }
}
