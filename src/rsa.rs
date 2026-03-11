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

#[cfg(feature = "openssl")]
mod openssl_imp;
#[cfg(any(
    all(feature = "rsa", not(feature = "openssl")),
    all(test, feature = "rsa", feature = "openssl")
))]
mod rustcrypto_imp;

#[cfg(feature = "openssl")]
pub use openssl_imp::*;
#[cfg(all(feature = "rsa", not(feature = "openssl")))]
pub use rustcrypto_imp::*;

#[cfg(all(test, feature = "rsa", feature = "openssl"))]
mod interop_tests {
    use super::{openssl_imp, rustcrypto_imp, RsaAlgorithm};
    use crate::{
        PrivateKeyToJwk, PublicKeyToJwk, SigningKey, VerificationKey, URL_SAFE_TRAILING_BITS,
    };
    use base64::Engine as _;
    use openssl::{bn::BigNum, pkey::PKey, rsa::RsaPrivateKeyBuilder};

    fn decode_pub_jwk(jwk: &crate::jwk::Jwk) -> (Vec<u8>, Vec<u8>) {
        let n = URL_SAFE_TRAILING_BITS
            .decode(jwk.n.as_deref().expect("RSA n is present"))
            .expect("decode n");
        let e = URL_SAFE_TRAILING_BITS
            .decode(jwk.e.as_deref().expect("RSA e is present"))
            .expect("decode e");
        (n, e)
    }

    fn decode_private_jwk(jwk: &crate::jwk::Jwk) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let (n, e) = decode_pub_jwk(jwk);
        let d = URL_SAFE_TRAILING_BITS
            .decode(jwk.d.as_deref().expect("RSA d is present"))
            .expect("decode d");
        (n, e, d)
    }

    #[test]
    fn public_jwk_interop_between_backends() -> crate::Result<()> {
        for alg in [
            RsaAlgorithm::RS256,
            RsaAlgorithm::RS384,
            RsaAlgorithm::RS512,
            RsaAlgorithm::PS256,
            RsaAlgorithm::PS384,
            RsaAlgorithm::PS512,
        ] {
            let openssl_k = openssl_imp::RsaPrivateKey::generate(2048, alg)?;
            let openssl_pub_jwk = openssl_k.public_key_to_jwk()?;
            let (n, e) = decode_pub_jwk(&openssl_pub_jwk);
            let rust_pk = rustcrypto_imp::RsaPublicKey::from_components(&n, &e, Some(alg))?;
            let sig = openssl_k.sign(b"openssl->rustcrypto")?;
            rust_pk.verify(b"openssl->rustcrypto", &sig, alg.name())?;

            let rust_k = rustcrypto_imp::RsaPrivateKey::generate(2048, alg)?;
            let rust_pub_jwk = rust_k.public_key_to_jwk()?;
            let (n, e) = decode_pub_jwk(&rust_pub_jwk);
            let openssl_pk = openssl_imp::RsaPublicKey::from_components(&n, &e, Some(alg))?;
            let sig = rust_k.sign(b"rustcrypto->openssl")?;
            openssl_pk.verify(b"rustcrypto->openssl", &sig, alg.name())?;
        }
        Ok(())
    }

    #[test]
    fn private_jwk_interop_between_backends() -> crate::Result<()> {
        for alg in [RsaAlgorithm::RS256, RsaAlgorithm::PS256] {
            let openssl_k = openssl_imp::RsaPrivateKey::generate(2048, alg)?;
            let openssl_jwk = openssl_k.private_key_to_jwk()?;
            let (n, e, d) = decode_private_jwk(&openssl_jwk);
            let rust_k = rustcrypto_imp::RsaPrivateKey::from_components(&n, &e, &d, vec![], alg)?;
            let sig = rust_k.sign(b"openssl-jwk->rustcrypto-key")?;
            openssl_k.verify(b"openssl-jwk->rustcrypto-key", &sig, alg.name())?;

            let rust_jwk = rust_k.private_key_to_jwk()?;
            let (n, e, d) = decode_private_jwk(&rust_jwk);
            let rsa = RsaPrivateKeyBuilder::new(
                BigNum::from_slice(&n)?,
                BigNum::from_slice(&e)?,
                BigNum::from_slice(&d)?,
            )?
            .build();
            let pkey = PKey::from_rsa(rsa)?;
            let openssl_k_from_jwk =
                openssl_imp::RsaPrivateKey::from_pkey_without_check(pkey, alg)?;
            let sig = openssl_k_from_jwk.sign(b"rustcrypto-jwk->openssl-key")?;
            rust_k.verify(b"rustcrypto-jwk->openssl-key", &sig, alg.name())?;
        }
        Ok(())
    }
}
