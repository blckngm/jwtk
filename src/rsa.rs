use crate::{Error, Result};

/// RSA signature algorithms.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaAlgorithm {
    RS256,
    RS384,
    RS512,
    PS256,
    PS384,
    PS512,
}

impl RsaAlgorithm {
    pub fn is_pss(self) -> bool {
        matches!(
            self,
            RsaAlgorithm::PS256 | RsaAlgorithm::PS384 | RsaAlgorithm::PS512
        )
    }

    pub fn name(self) -> &'static str {
        use RsaAlgorithm::*;
        match self {
            RS256 => "RS256",
            RS384 => "RS384",
            RS512 => "RS512",
            PS256 => "PS256",
            PS384 => "PS384",
            PS512 => "PS512",
        }
    }

    pub fn from_name(name: &str) -> Result<Self> {
        Ok(match name {
            "RS256" => RsaAlgorithm::RS256,
            "RS384" => RsaAlgorithm::RS384,
            "RS512" => RsaAlgorithm::RS512,
            "PS256" => RsaAlgorithm::PS256,
            "PS384" => RsaAlgorithm::PS384,
            "PS512" => RsaAlgorithm::PS512,
            _ => return Err(Error::UnsupportedOrInvalidKey),
        })
    }
}

#[cfg(any(
    all(feature = "aws-lc", not(feature = "openssl")),
    all(test, feature = "aws-lc", feature = "openssl")
))]
mod aws_lc_imp;
#[cfg(feature = "openssl")]
mod openssl_imp;

#[cfg(feature = "openssl")]
pub use openssl_imp::*;

#[cfg(all(feature = "aws-lc", not(feature = "openssl")))]
pub use aws_lc_imp::RsaPublicKey;

#[cfg(all(test, feature = "aws-lc", feature = "openssl"))]
mod aws_lc_interop_tests {
    use super::{aws_lc_imp, openssl_imp, RsaAlgorithm};
    use crate::{PublicKeyToJwk, SigningKey, VerificationKey, URL_SAFE_TRAILING_BITS};
    use base64::Engine as _;

    #[test]
    fn verify_openssl_sig_with_aws_lc() -> crate::Result<()> {
        for alg in [
            RsaAlgorithm::RS256,
            RsaAlgorithm::RS384,
            RsaAlgorithm::RS512,
            RsaAlgorithm::PS256,
            RsaAlgorithm::PS384,
            RsaAlgorithm::PS512,
        ] {
            let k = openssl_imp::RsaPrivateKey::generate(2048, alg)?;
            let pub_jwk = k.public_key_to_jwk()?;
            let n = URL_SAFE_TRAILING_BITS
                .decode(pub_jwk.n.as_deref().unwrap())
                .unwrap();
            let e = URL_SAFE_TRAILING_BITS
                .decode(pub_jwk.e.as_deref().unwrap())
                .unwrap();
            let aws_pk = aws_lc_imp::RsaPublicKey::from_components(&n, &e, Some(alg))?;
            let sig = k.sign(b"openssl->aws-lc")?;
            aws_pk.verify(b"openssl->aws-lc", &sig, alg.name())?;
        }
        Ok(())
    }
}
