use openssl::{
    bn::BigNum,
    hash::MessageDigest,
    pkey::{PKey, Private, Public},
    rsa::Rsa,
    sign::{Signer, Verifier},
};
use smallvec::SmallVec;

use crate::{
    jwk::{Jwk, PublicKeyToJwk},
    url_safe_trailing_bits, Error, Result, SigningKey, VerificationKey,
};

#[derive(Debug)]
pub struct RS256PrivateKey(pub(crate) PKey<Private>);

impl RS256PrivateKey {
    /// Recommended bits >= 2048.
    pub fn generate(bits: u32) -> Result<Self> {
        Ok(Self(PKey::from_rsa(Rsa::generate(bits)?)?))
    }

    pub fn from_pem(pem: &[u8]) -> Result<Self> {
        let pk = PKey::private_key_from_pem(pem)?;
        if !pk.rsa()?.check_key()? {
            return Err(Error::UnsupportedOrInvalidKey);
        }
        Ok(Self(pk))
    }

    pub fn private_key_to_pem_pkcs8(&self) -> Result<Vec<u8>> {
        Ok(self.0.private_key_to_pem_pkcs8()?)
    }

    pub fn public_key_pem(&self) -> Result<Vec<u8>> {
        Ok(self.0.public_key_to_pem()?)
    }

    pub fn public_key_pem_pkcs1(&self) -> Result<Vec<u8>> {
        Ok(self.0.rsa()?.public_key_to_pem_pkcs1()?)
    }

    pub fn n(&self) -> Result<Vec<u8>> {
        Ok(self.0.rsa()?.n().to_vec())
    }

    pub fn e(&self) -> Result<Vec<u8>> {
        Ok(self.0.rsa()?.e().to_vec())
    }
}

#[derive(Debug)]
pub struct RS256PublicKey(pub(crate) PKey<Public>);

impl RS256PublicKey {
    /// BEGIN PUBLIC KEY
    pub fn from_pem(pem: &[u8]) -> Result<Self> {
        Ok(Self(PKey::from_rsa(Rsa::public_key_from_pem(pem)?)?))
    }

    /// BEGIN RSA PUBLIC KEY
    pub fn from_pem_pkcs1(pem: &[u8]) -> Result<Self> {
        Ok(Self(PKey::from_rsa(Rsa::public_key_from_pem_pkcs1(pem)?)?))
    }

    pub fn from_components(n: &[u8], e: &[u8]) -> Result<Self> {
        let rsa = Rsa::from_public_components(BigNum::from_slice(n)?, BigNum::from_slice(e)?)?;
        Ok(Self(PKey::from_rsa(rsa)?))
    }

    /// BEGIN PUBLIC KEY
    pub fn to_pem(&self) -> Result<Vec<u8>> {
        Ok(self.0.public_key_to_pem()?)
    }

    /// BEGIN RSA PUBLIC KEY
    pub fn to_pem_pkcs1(&self) -> Result<Vec<u8>> {
        Ok(self.0.rsa()?.public_key_to_pem_pkcs1()?)
    }

    pub fn n(&self) -> Result<Vec<u8>> {
        Ok(self.0.rsa()?.n().to_vec())
    }

    pub fn e(&self) -> Result<Vec<u8>> {
        Ok(self.0.rsa()?.e().to_vec())
    }
}

impl SigningKey for RS256PrivateKey {
    fn sign(&self, v: &[u8]) -> Result<SmallVec<[u8; 64]>> {
        let mut signer = Signer::new(MessageDigest::sha256(), self.0.as_ref())?;

        signer.update(v)?;
        Ok(signer.sign_to_vec()?.into())
    }

    fn alg(&self) -> &'static str {
        "RS256"
    }
}

impl VerificationKey for RS256PrivateKey {
    fn verify(&self, v: &[u8], sig: &[u8]) -> Result<()> {
        let mut verifier = Verifier::new(MessageDigest::sha256(), self.0.as_ref())?;
        if verifier.verify_oneshot(sig, v)? {
            Ok(())
        } else {
            Err(Error::VerificationError)
        }
    }

    #[inline]
    fn alg(&self) -> &'static str {
        "RS256"
    }
}

impl VerificationKey for RS256PublicKey {
    fn verify(&self, v: &[u8], sig: &[u8]) -> Result<()> {
        let mut verifier = Verifier::new(MessageDigest::sha256(), self.0.as_ref())?;
        if verifier.verify_oneshot(sig, v)? {
            Ok(())
        } else {
            Err(Error::VerificationError)
        }
    }

    #[inline]
    fn alg(&self) -> &'static str {
        "RS256"
    }
}

impl PublicKeyToJwk for RS256PrivateKey {
    fn to_jwk(&self) -> Result<Jwk> {
        Ok(Jwk {
            kty: "RSA".into(),
            alg: Some("RS256".into()),
            use_: Some("sig".into()),
            n: Some(base64::encode_config(self.n()?, url_safe_trailing_bits())),
            e: Some(base64::encode_config(self.e()?, url_safe_trailing_bits())),
            ..Jwk::default()
        })
    }
}

impl PublicKeyToJwk for RS256PublicKey {
    fn to_jwk(&self) -> Result<Jwk> {
        Ok(Jwk {
            kty: "RSA".into(),
            alg: Some("RS256".into()),
            use_: Some("sig".into()),
            n: Some(base64::encode_config(self.n()?, url_safe_trailing_bits())),
            e: Some(base64::encode_config(self.e()?, url_safe_trailing_bits())),
            ..Jwk::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::es256::ES256PrivateKey;

    use super::*;

    #[test]
    fn conversion() -> Result<()> {
        let k = RS256PrivateKey::generate(2048)?;
        let pem = k.private_key_to_pem_pkcs8()?;
        RS256PrivateKey::from_pem(&pem)?;

        let es256key_pem = ES256PrivateKey::generate()?.0.private_key_to_pem_pkcs8()?;
        assert!(RS256PrivateKey::from_pem(&es256key_pem).is_err());

        let pk_pem = k.public_key_pem()?;
        let pk_pem_pkcs1 = k.public_key_pem_pkcs1()?;

        let pk = RS256PublicKey::from_pem(&pk_pem)?;
        let pk1 = RS256PublicKey::from_pem_pkcs1(&pk_pem_pkcs1)?;

        println!("k: {:?}, pk: {:?}", k, pk);

        let pk_pem1 = pk1.to_pem()?;
        let pk_pem_pkcs1_1 = pk.to_pem_pkcs1()?;

        assert_eq!(pk_pem, pk_pem1);
        assert_eq!(pk_pem_pkcs1, pk_pem_pkcs1_1);

        assert_eq!(VerificationKey::alg(&k), "RS256");
        assert_eq!(SigningKey::alg(&k), "RS256");
        assert_eq!(pk.alg(), "RS256");

        k.to_jwk()?.to_verification_key()?;
        pk.to_jwk()?;

        Ok(())
    }

    #[test]
    fn sign_verify() -> Result<()> {
        let k = RS256PrivateKey::generate(2048)?;
        let pk = RS256PublicKey::from_pem(&k.public_key_pem()?)?;
        let sig = k.sign(b"...")?;
        assert!(k.verify(b"...", &sig).is_ok());
        assert!(k.verify(b"....", &sig).is_err());
        assert!(pk.verify(b"...", &sig).is_ok());
        assert!(pk.verify(b"....", &sig).is_err());
        Ok(())
    }
}
