#![doc = include_str!("../README.md")]

use openssl::error::ErrorStack;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{Map, Value};
use serde_with::{serde_as, skip_serializing_none};
use smallvec::SmallVec;
use std::{
    borrow::Cow,
    fmt,
    io::Write,
    string::FromUtf8Error,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use jwk::Jwk;
pub use some::*;

mod some;

pub mod hmac;

pub mod eddsa;

pub mod ecdsa;

pub mod rsa;

pub mod jwk;

/// JWT header.
#[non_exhaustive]
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Header {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,

    pub alg: Cow<'static, str>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,

    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum OneOrMany<T> {
    /// Single value
    One(T),
    /// Array of values
    Vec(Vec<T>),
}

impl<T> OneOrMany<T> {
    #[inline]
    fn is_empty(&self) -> bool {
        matches!(self, OneOrMany::Vec(v) if v.is_empty())
    }

    /// Iterate over the values regardless of whether it contains one or many.
    #[inline]
    pub fn iter(&self) -> OneOrManyIter<T> {
        OneOrManyIter::new(self)
    }
}

impl<T> Default for OneOrMany<T> {
    #[inline]
    fn default() -> Self {
        Self::Vec(Vec::new())
    }
}

pub struct OneOrManyIter<'a, T> {
    one: Option<&'a T>,
    many: Option<std::slice::Iter<'a, T>>,
}

impl<'a, T> OneOrManyIter<'a, T> {
    fn new(inner: &'a OneOrMany<T>) -> Self {
        match inner {
            OneOrMany::One(v) => Self {
                one: Some(v),
                many: None,
            },
            OneOrMany::Vec(v) => Self {
                one: None,
                many: Some(v.iter()),
            },
        }
    }
}

impl<'a, T> Iterator for OneOrManyIter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(one) = self.one.take() {
            return Some(one);
        }
        self.many.as_mut().and_then(|iter| iter.next())
    }
}

/// JWT Claims.
#[serde_as]
#[skip_serializing_none]
#[non_exhaustive]
#[derive(Debug, Serialize, Default, Deserialize)]
pub struct Claims<ExtraClaims> {
    #[serde_as(as = "Option<serde_with::DurationSeconds<f64>>")]
    pub exp: Option<Duration>,
    #[serde_as(as = "Option<serde_with::DurationSeconds<f64>>")]
    pub nbf: Option<Duration>,
    #[serde_as(as = "Option<serde_with::DurationSeconds<f64>>")]
    pub iat: Option<Duration>,

    pub iss: Option<String>,
    pub sub: Option<String>,
    #[serde(default, skip_serializing_if = "OneOrMany::is_empty")]
    pub aud: OneOrMany<String>,
    pub jti: Option<String>,

    #[serde(flatten)]
    pub extra: ExtraClaims,
}

/// JWT header and claims.
///
/// # `ExtraClaims`
///
/// Use `serde_json::Map<String, Value>` for dynamic claims.
///
/// Or define your own claims type which implements `Serialize`/`Deserialize`.
#[derive(Default, Debug)]
pub struct HeaderAndClaims<ExtraClaims> {
    header: Header,
    claims: Claims<ExtraClaims>,
}

impl HeaderAndClaims<Map<String, Value>> {
    #[inline]
    pub fn new_dynamic() -> Self {
        Self::default()
    }
}

macro_rules! define_setter {
    ($setter_name:ident, $field:ident) => {
        #[inline]
        pub fn $setter_name(&mut self, $field: impl Into<String>) -> &mut Self {
            self.claims.$field = Some($field.into());
            self
        }
    };
}

impl<ExtraClaims> HeaderAndClaims<ExtraClaims> {
    #[inline]
    pub fn with_claims(extra: ExtraClaims) -> Self {
        Self {
            header: Header::default(),
            claims: Claims {
                aud: Default::default(),
                exp: None,
                iat: None,
                iss: None,
                jti: None,
                nbf: None,
                sub: None,
                extra,
            },
        }
    }

    #[inline]
    pub fn header(&self) -> &Header {
        &self.header
    }

    #[inline]
    pub fn claims(&self) -> &Claims<ExtraClaims> {
        &self.claims
    }

    #[inline]
    pub fn header_mut(&mut self) -> &mut Header {
        &mut self.header
    }

    #[inline]
    pub fn claims_mut(&mut self) -> &mut Claims<ExtraClaims> {
        &mut self.claims
    }

    #[inline]
    pub fn set_kid(&mut self, kid: impl Into<String>) -> &mut Self {
        self.header.kid = Some(kid.into());
        self
    }

    define_setter!(set_iss, iss);
    define_setter!(set_sub, sub);
    define_setter!(set_jti, jti);

    #[inline]
    pub fn set_auds(&mut self, auds: Vec<String>) -> &mut Self {
        self.claims.aud = OneOrMany::Vec(auds);
        self
    }

    #[inline]
    pub fn add_aud(&mut self, aud: impl Into<String>) -> &mut Self {
        match &mut self.claims.aud {
            OneOrMany::One(a) => {
                self.claims.aud = OneOrMany::Vec(vec![std::mem::take(a), aud.into()])
            }
            OneOrMany::Vec(v) => v.push(aud.into()),
        }
        self
    }

    /// Set token issued-at time (`iat`) to the current system time, i.e.
    /// `SystemTime::now()`.
    pub fn set_iat_now(&mut self) -> &mut Self {
        self.claims.iat = Some(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap(),
        );
        self
    }

    /// Check that `iat` is present and is later than `t`.
    pub fn iat_is_later_than(&self, t: SystemTime) -> bool {
        self.claims
            .iat
            .map_or(false, |iat| iat > t.duration_since(UNIX_EPOCH).unwrap())
    }

    /// Set token expiration time (`exp`) to some time after the current time,
    /// i.e., `SystemTime::now() + dur`.
    pub fn set_exp_from_now(&mut self, dur: Duration) -> &mut Self {
        let t = (SystemTime::now() + dur)
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();
        self.claims.exp = Some(t);
        self
    }

    /// Set token not-before time (`nbf`) to some time after the current time,
    /// i.e., `SystemTime::now() + dur`.
    pub fn set_nbf_from_now(&mut self, dur: Duration) -> &mut Self {
        let t = (SystemTime::now() + dur)
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();
        self.claims.nbf = Some(t);
        self
    }
}

impl HeaderAndClaims<Map<String, Value>> {
    #[inline]
    pub fn insert(&mut self, k: impl Into<String>, v: impl Into<Value>) -> &mut Self {
        self.claims.extra.insert(k.into(), v.into());
        self
    }
}

#[inline(always)]
fn url_safe_trailing_bits() -> base64::Config {
    base64::URL_SAFE_NO_PAD.decode_allow_trailing_bits(true)
}

/// Encode and sign this header and claims with the signing key.
///
/// The `alg` field in header is automatically set. The `kid` claim is
/// automatically set if the key has an id.
///
/// Returns a signed JWT.
pub fn sign<ExtraClaims: Serialize>(
    claims: &mut HeaderAndClaims<ExtraClaims>,
    k: &dyn SigningKey,
) -> Result<String> {
    claims.header.alg = k.alg().into();
    if let Some(kid) = k.kid() {
        claims.set_kid(kid);
    }

    let mut w = base64::write::EncoderStringWriter::new(url_safe_trailing_bits());
    serde_json::to_writer(&mut w, &claims.header)?;

    let mut buf = w.into_inner();
    buf.push('.');
    let mut w = base64::write::EncoderStringWriter::from(buf, url_safe_trailing_bits());

    serde_json::to_writer(&mut w, &claims.claims)?;
    let mut buf = w.into_inner();

    let sig = k.sign(buf.as_bytes())?;

    buf.push('.');

    let mut w = base64::write::EncoderStringWriter::from(buf, url_safe_trailing_bits());
    w.write_all(&sig)?;
    Ok(w.into_inner())
}

/// Decode and verify token.
///
/// The `alg`, `exp` and `nbf` fields are automatically checked.
pub fn verify<ExtraClaims: DeserializeOwned>(
    token: &str,
    k: &dyn VerificationKey,
) -> Result<HeaderAndClaims<ExtraClaims>> {
    let claims = verify_only(token, k)?;

    // Check exp and nbf.
    let now = SystemTime::now();
    if let Some(exp) = claims.claims.exp {
        let exp = SystemTime::UNIX_EPOCH + exp;
        if now > exp {
            return Err(Error::Expired);
        }
    }
    if let Some(nbf) = claims.claims.nbf {
        let nbf = SystemTime::UNIX_EPOCH + nbf;
        if now < nbf {
            return Err(Error::Before);
        }
    }

    Ok(claims)
}

/// Decode and verify token, but do not check `exp` and `nbf`.
///
/// The `alg` field is still checked.
pub fn verify_only<ExtraClaims: DeserializeOwned>(
    token: &str,
    k: &dyn VerificationKey,
) -> Result<HeaderAndClaims<ExtraClaims>> {
    let mut parts = token.split('.');

    let mut header = parts.next().ok_or(Error::InvalidToken)?.as_bytes();
    let mut payload = parts.next().ok_or(Error::InvalidToken)?.as_bytes();
    let header_and_payload_len = header.len() + payload.len() + 1;
    let sig = parts.next().ok_or(Error::InvalidToken)?;
    if parts.next().is_some() {
        return Err(Error::InvalidToken);
    }

    let header_r = base64::read::DecoderReader::new(&mut header, url_safe_trailing_bits());
    let header: Header = serde_json::from_reader(header_r)?;

    let sig = base64::decode_config(sig, url_safe_trailing_bits())?;

    // Verify the signature.
    k.verify(
        token[..header_and_payload_len].as_bytes(),
        &sig,
        &header.alg,
    )?;

    let payload_r = base64::read::DecoderReader::new(&mut payload, url_safe_trailing_bits());
    let claims: Claims<ExtraClaims> = serde_json::from_reader(payload_r)?;

    Ok(HeaderAndClaims { header, claims })
}

/// Decode token.
///
/// No verification or validation is performed.
pub fn decode_without_verify<ExtraClaims: DeserializeOwned>(
    token: &str,
) -> Result<HeaderAndClaims<ExtraClaims>> {
    let mut parts = token.split('.');

    let mut header = parts.next().ok_or(Error::InvalidToken)?.as_bytes();
    let mut payload = parts.next().ok_or(Error::InvalidToken)?.as_bytes();
    let _sig = parts.next().ok_or(Error::InvalidToken)?;
    if parts.next().is_some() {
        return Err(Error::InvalidToken);
    }

    let header_r = base64::read::DecoderReader::new(&mut header, url_safe_trailing_bits());
    let header: Header = serde_json::from_reader(header_r)?;

    let payload_r = base64::read::DecoderReader::new(&mut payload, url_safe_trailing_bits());
    let claims: Claims<ExtraClaims> = serde_json::from_reader(payload_r)?;

    Ok(HeaderAndClaims { header, claims })
}

pub trait SigningKey {
    // A signing key has a rigid algorithm.
    fn alg(&self) -> &'static str;

    /// Optional key id. If it is present, then it is automatically set in
    /// header claims.
    fn kid(&self) -> Option<&str> {
        None
    }

    // Es256 and eddsa signatures are 64-byte long.
    fn sign(&self, v: &[u8]) -> Result<SmallVec<[u8; 64]>>;
}

pub trait VerificationKey {
    // `alg` is passed in because HMAC and RSA verification keys can verify
    // signatures generated with multiple algorithms.
    fn verify(&self, v: &[u8], sig: &[u8], alg: &str) -> Result<()>;
}

pub trait PublicKeyToJwk {
    fn public_key_to_jwk(&self) -> Result<Jwk>;
}

pub trait PrivateKeyToJwk {
    fn private_key_to_jwk(&self) -> Result<Jwk>;
}

#[non_exhaustive]
#[derive(Debug)]
pub enum Error {
    InvalidToken,
    VerificationError,
    AlgMismatch,
    NoKid,
    NoKey,
    Expired,
    /// The token is not valid yet , i.e. `nbf` check failed.
    Before,
    UnsupportedOrInvalidKey,
    Utf8(FromUtf8Error),
    IoError(std::io::Error),
    OpenSsl(ErrorStack),
    SerdeJson(serde_json::Error),
    Decode(base64::DecodeError),
    #[cfg(feature = "remote-jwks")]
    Reqwest(reqwest::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::IoError(e) => e.fmt(f),
            Error::OpenSsl(e) => e.fmt(f),
            Error::SerdeJson(e) => e.fmt(f),
            Error::Decode(e) => e.fmt(f),
            #[cfg(feature = "remote-jwks")]
            Error::Reqwest(e) => e.fmt(f),
            Error::Utf8(e) => e.fmt(f),
            Error::VerificationError => "failed to verify signature".fmt(f),
            Error::AlgMismatch => {
                "the alg field in JWT header is different from what the verification key uses"
                    .fmt(f)
            }
            Error::InvalidToken => "the token not in a valid format".fmt(f),
            Error::NoKid => "the kid field is missing from the JWT header".fmt(f),
            Error::NoKey => "no key in the JWK Set matches the kid".fmt(f),
            Error::UnsupportedOrInvalidKey => "unsupported or invalid key".fmt(f),
            Error::Expired => "token expired (exp check failed)".fmt(f),
            Error::Before => "token is not valid yet (nbf check failed)".fmt(f),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::IoError(e) => Some(e),
            Error::OpenSsl(e) => Some(e),
            Error::SerdeJson(e) => Some(e),
            Error::Decode(e) => Some(e),
            Error::Utf8(e) => Some(e),
            #[cfg(feature = "remote-jwks")]
            Error::Reqwest(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    #[inline]
    fn from(e: std::io::Error) -> Error {
        Error::IoError(e)
    }
}

impl From<ErrorStack> for Error {
    #[inline]
    fn from(e: ErrorStack) -> Error {
        Error::OpenSsl(e)
    }
}

impl From<serde_json::Error> for Error {
    #[inline]
    fn from(e: serde_json::Error) -> Error {
        Error::SerdeJson(e)
    }
}

impl From<base64::DecodeError> for Error {
    #[inline]
    fn from(e: base64::DecodeError) -> Self {
        Error::Decode(e)
    }
}

impl From<FromUtf8Error> for Error {
    #[inline]
    fn from(e: FromUtf8Error) -> Self {
        Error::Utf8(e)
    }
}

#[cfg(feature = "remote-jwks")]
impl From<reqwest::Error> for Error {
    #[inline]
    fn from(e: reqwest::Error) -> Self {
        Error::Reqwest(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use crate::ecdsa::{EcdsaAlgorithm, EcdsaPrivateKey};

    use super::*;

    #[test]
    fn one_or_many_iterator() {
        let v = OneOrMany::Vec(vec![1, 2, 3]);
        let mut iter = v.iter();
        assert_eq!(iter.next(), Some(&1));
        assert_eq!(iter.next(), Some(&2));
        assert_eq!(iter.next(), Some(&3));
        assert_eq!(iter.next(), None);

        let v = OneOrMany::One(1);
        let mut iter = v.iter();
        assert_eq!(iter.next(), Some(&1));
        assert_eq!(iter.next(), None);
    } 

    #[test]
    fn signing_and_verification() -> Result<()> {
        let mut claims = HeaderAndClaims::new_dynamic();
        let k = EcdsaPrivateKey::generate(EcdsaAlgorithm::ES256)?;
        let k1 = EcdsaPrivateKey::generate(EcdsaAlgorithm::ES256)?;
        claims
            .set_exp_from_now(Duration::from_secs(3))
            .set_nbf_from_now(Duration::from_secs(1))
            .set_iss("me")
            .set_sub("you")
            .add_aud("him")
            .add_aud("her")
            .set_jti("jti")
            .set_kid("kid")
            .set_iat_now()
            .insert("foo", "bar")
            .insert("baz", 9);
        let token = sign(&mut claims, &k)?;

        decode_without_verify::<Map<String, Value>>(&token)?;

        assert!(verify::<Map<String, Value>>(&token, &k).is_err());
        assert!(verify_only::<Map<String, Value>>(&token, &k).is_ok());
        std::thread::sleep(Duration::from_secs(2));
        assert!(verify::<Map<String, Value>>(&token, &k).is_ok());
        assert!(verify::<Map<String, Value>>(&token, &k1).is_err());
        std::thread::sleep(Duration::from_secs(2));
        assert!(verify::<Map<String, Value>>(&token, &k).is_err());
        assert!(verify_only::<Map<String, Value>>(&token, &k).is_ok());

        Ok(())
    }

    #[test]
    fn claim_deserialization() {
        let mut json = r#"eyJpYXQiOjEuNjkyMTkwMTI1RTksImV4cCI6MS42OTIxOTM3MjVFOSwiYW50aUNzcmZUb2tlbiI6bnVsbCwic3ViIjoiYTM5ZmZjNWUtNjc5ZC00YjAzLWI5YmYtYTliZjEzNDk4NGYzIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDozOTk5L2F1dGgiLCJzZXNzaW9uSGFuZGxlIjoiNTAyMWQ2MTQtYzFmNi00ZTZkLWI1NjktZGQxN2Q0N2EyOWI0IiwicGFyZW50UmVmcmVzaFRva2VuSGFzaDEiOm51bGwsInJlZnJlc2hUb2tlbkhhc2gxIjoiNTZiMjcxZDcxNGRlMzg3M2UwMmIyZjAyYTJiZDcyYWJjZDIyZDM0NGZlZjE2YTJkMWJjYmM1NGU2YWUxN2M3OCJ9"#.as_bytes();

        let r = base64::read::DecoderReader::new(&mut json, url_safe_trailing_bits());

        let claims: Claims<Value> = serde_json::from_reader(r).unwrap();
        assert_eq!(claims.iat, Some(Duration::from_secs(1692190125)));
        assert_eq!(claims.exp, Some(Duration::from_secs(1692193725)));
    }
}
