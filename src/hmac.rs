use openssl::{hash::MessageDigest, memcmp, pkey::PKey, rand::rand_bytes, sign::Signer};
use smallvec::{smallvec, SmallVec};

use crate::{jwk::Jwk, Error, Result, SigningKey, VerificationKey};

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HmacAlgorithm {
    HS256,
    HS384,
    HS512,
}

impl HmacAlgorithm {
    fn name(self) -> &'static str {
        use HmacAlgorithm::*;
        match self {
            HS256 => "HS256",
            HS384 => "HS384",
            HS512 => "HS512",
        }
    }

    fn digest(self) -> MessageDigest {
        use HmacAlgorithm::*;
        match self {
            HS256 => MessageDigest::sha256(),
            HS384 => MessageDigest::sha384(),
            HS512 => MessageDigest::sha512(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct HmacKey {
    k: SmallVec<[u8; 32]>,
    algorithm: HmacAlgorithm,
}

impl HmacKey {
    #[inline]
    pub fn generate(algorithm: HmacAlgorithm) -> Result<Self> {
        let len = match algorithm {
            HmacAlgorithm::HS256 => 32,
            HmacAlgorithm::HS384 => 48,
            HmacAlgorithm::HS512 => 64,
        };

        let mut k = smallvec![0u8; len];
        rand_bytes(&mut k)?;

        Ok(Self { k, algorithm })
    }

    /// The key should have enough entropy. At least 32-byte of full entropy is
    /// recommended.
    #[inline]
    pub fn from_bytes(k: &[u8], algorithm: HmacAlgorithm) -> Self {
        Self {
            k: k.into(),
            algorithm,
        }
    }

    #[inline]
    pub fn serialize(&self) -> &[u8] {
        &self.k
    }
}

impl SigningKey for HmacKey {
    fn sign(&self, v: &[u8]) -> Result<SmallVec<[u8; 64]>> {
        let pk = PKey::hmac(&self.k)?;
        let mut signer = Signer::new(self.algorithm.digest(), pk.as_ref())?;

        let mut sig = smallvec![0u8; signer.len()?];
        signer.sign_oneshot(&mut sig, v)?;
        Ok(sig)
    }

    fn public_key_to_jwk(&self) -> Result<Jwk> {
        Err(Error::UnsupportedOrInvalidKey)
    }

    #[inline]
    fn alg(&self) -> &'static str {
        self.algorithm.name()
    }
}

impl VerificationKey for HmacKey {
    fn verify(&self, v: &[u8], sig: &[u8], alg: &str) -> Result<()> {
        if alg != self.algorithm.name() {
            return Err(Error::VerificationError);
        }

        let expected = self.sign(v)?;

        if memcmp::eq(sig, &expected) {
            Ok(())
        } else {
            Err(Error::VerificationError)
        }
    }

    fn public_key_to_jwk(&self) -> Result<Jwk> {
        Err(Error::UnsupportedOrInvalidKey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversion() -> Result<()> {
        let k = HmacKey::generate(HmacAlgorithm::HS384)?;
        assert_eq!(SigningKey::alg(&k), "HS384");
        let k1 = k.clone();
        let k1 = k1.serialize();
        HmacKey::from_bytes(k1, HmacAlgorithm::HS256);
        println!("{:?}", k);
        Ok(())
    }

    #[test]
    fn sign_and_verify() -> Result<()> {
        for alg in std::array::IntoIter::new([
            HmacAlgorithm::HS256,
            HmacAlgorithm::HS384,
            HmacAlgorithm::HS512,
        ]) {
            let k = HmacKey::from_bytes(b"key", alg);
            let sig = k.sign(b"...")?;
            assert!(k.verify(b"...", &sig, alg.name()).is_ok());
            assert!(k.verify(b"...", &sig, "WRONG ALG").is_err());
            assert!(k.verify(b"....", &sig, alg.name()).is_err());
        }
        Ok(())
    }
}
