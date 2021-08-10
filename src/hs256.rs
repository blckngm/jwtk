use openssl::{hash::MessageDigest, memcmp, pkey::PKey, rand::rand_bytes, sign::Signer};
use smallvec::SmallVec;

use crate::{Error, Result, SigningKey, VerificationKey};

#[derive(Debug, Clone)]
pub struct HS256Key(SmallVec<[u8; 32]>);

impl HS256Key {
    #[inline]
    pub fn generate() -> Result<Self> {
        let mut k = [0u8; 32];
        rand_bytes(&mut k)?;

        Ok(Self(k.into()))
    }

    /// It is recommended that the key contains 32 bytes of full-entropy.
    #[inline]
    pub fn from_bytes(k: &[u8]) -> Self {
        HS256Key(k.into())
    }

    #[inline]
    pub fn serialize(&self) -> &[u8] {
        &self.0
    }
}

impl SigningKey for HS256Key {
    fn sign(&self, v: &[u8]) -> Result<SmallVec<[u8; 64]>> {
        let pk = PKey::hmac(&self.0)?;

        let mut sig = [0u8; 32];

        let mut signer = Signer::new(MessageDigest::sha256(), pk.as_ref())?;

        signer.sign_oneshot(&mut sig, v)?;
        Ok(sig[..].into())
    }

    #[inline]
    fn alg(&self) -> &'static str {
        "HS256"
    }
}

impl VerificationKey for HS256Key {
    fn verify(&self, v: &[u8], sig: &[u8]) -> Result<()> {
        let expected = self.sign(v)?;

        if memcmp::eq(sig, &expected) {
            Ok(())
        } else {
            Err(Error::VerificationError)
        }
    }

    #[inline]
    fn alg(&self) -> &'static str {
        "HS256"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversion() -> Result<()> {
        let k = HS256Key::generate()?;
        assert_eq!(SigningKey::alg(&k), "HS256");
        assert_eq!(VerificationKey::alg(&k), "HS256");
        let k1 = k.clone();
        let k1 = k1.serialize();
        HS256Key::from_bytes(k1);
        println!("{:?}", k);
        Ok(())
    }

    #[test]
    fn sign_and_verify() -> Result<()> {
        let k = HS256Key::from_bytes(b"key");
        let sig = k.sign(b"...")?;
        assert!(k.verify(b"...", &sig).is_ok());
        assert!(k.verify(b"....", &sig).is_err());
        Ok(())
    }
}
