use std::ptr;

use foreign_types::ForeignType;
use openssl::{
    error::ErrorStack,
    pkey::{PKey, Private, Public},
    sign::{Signer, Verifier},
};
use smallvec::SmallVec;

use crate::{
    jwk::Jwk, url_safe_trailing_bits, Error, PrivateKeyToJwk, PublicKeyToJwk, Result, SigningKey,
    VerificationKey,
};

#[derive(Debug, Clone)]
pub struct Ed25519PrivateKey {
    private_key: PKey<Private>,
}

impl Ed25519PrivateKey {
    pub fn generate() -> Result<Self> {
        let pkey = PKey::generate_ed25519()?;
        Ok(Self { private_key: pkey })
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let pkey = unsafe {
            openssl_sys::EVP_PKEY_new_raw_private_key(
                openssl_sys::EVP_PKEY_ED25519,
                ptr::null_mut(),
                b.as_ptr(),
                b.len(),
            )
        };
        if pkey.is_null() {
            return Err(ErrorStack::get().into());
        }
        Ok(Self {
            private_key: unsafe { PKey::from_ptr(pkey) },
        })
    }

    pub(crate) fn from_pkey(pk: PKey<Private>) -> Result<Self> {
        if pk.id() != openssl::pkey::Id::ED25519 {
            return Err(Error::UnsupportedOrInvalidKey);
        }
        Ok(Self { private_key: pk })
    }

    pub fn from_pem(pem: &[u8]) -> Result<Self> {
        let pk = PKey::private_key_from_pem(pem)?;
        Self::from_pkey(pk)
    }

    pub fn private_key_bytes(&self) -> Result<[u8; 32]> {
        let mut out = [0u8; 32];
        let r = unsafe {
            openssl_sys::EVP_PKEY_get_raw_private_key(
                self.private_key.as_ptr(),
                out.as_mut_ptr(),
                &mut out.len(),
            )
        };
        if r == 0 {
            return Err(ErrorStack::get().into());
        }
        Ok(out)
    }

    pub fn public_key_bytes(&self) -> Result<[u8; 32]> {
        let mut out = [0u8; 32];
        let r = unsafe {
            openssl_sys::EVP_PKEY_get_raw_public_key(
                self.private_key.as_ptr(),
                out.as_mut_ptr(),
                &mut out.len(),
            )
        };
        if r == 0 {
            return Err(ErrorStack::get().into());
        }
        Ok(out)
    }

    pub fn private_key_to_pem_pkcs8(&self) -> Result<String> {
        Ok(String::from_utf8(
            self.private_key.private_key_to_pem_pkcs8()?,
        )?)
    }

    pub fn public_key_to_pem(&self) -> Result<String> {
        Ok(String::from_utf8(self.private_key.public_key_to_pem()?)?)
    }
}

impl PublicKeyToJwk for Ed25519PrivateKey {
    fn public_key_to_jwk(&self) -> Result<Jwk> {
        let bytes: [u8; 32] = self.public_key_bytes()?;
        Ok(Jwk {
            kty: "OKP".into(),
            crv: Some("Ed25519".into()),
            x: Some(base64::encode_config(&bytes, url_safe_trailing_bits())),
            ..Jwk::default()
        })
    }
}

impl PrivateKeyToJwk for Ed25519PrivateKey {
    fn private_key_to_jwk(&self) -> Result<Jwk> {
        let d = self.private_key_bytes()?;
        let x: [u8; 32] = self.public_key_bytes()?;
        Ok(Jwk {
            kty: "OKP".into(),
            crv: Some("Ed25519".into()),
            d: Some(base64::encode_config(&d, url_safe_trailing_bits())),
            x: Some(base64::encode_config(&x, url_safe_trailing_bits())),
            ..Jwk::default()
        })
    }
}

#[derive(Debug)]
pub struct Ed25519PublicKey {
    public_key: PKey<Public>,
}

impl Ed25519PublicKey {
    pub(crate) fn from_pkey(pkey: PKey<Public>) -> Result<Self> {
        if pkey.id() != openssl::pkey::Id::ED25519 {
            return Err(Error::UnsupportedOrInvalidKey);
        }
        Ok(Self { public_key: pkey })
    }

    pub fn from_pem(pem: &[u8]) -> Result<Self> {
        let pk = PKey::public_key_from_pem(pem)?;
        Self::from_pkey(pk)
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let pkey = unsafe {
            openssl_sys::EVP_PKEY_new_raw_public_key(
                openssl_sys::EVP_PKEY_ED25519,
                ptr::null_mut(),
                b.as_ptr(),
                b.len(),
            )
        };
        if pkey.is_null() {
            return Err(ErrorStack::get().into());
        }
        Ok(Self {
            public_key: unsafe { PKey::from_ptr(pkey) },
        })
    }

    pub fn to_pem(&self) -> Result<String> {
        Ok(String::from_utf8(self.public_key.public_key_to_pem()?)?)
    }

    pub fn to_bytes(&self) -> Result<[u8; 32]> {
        let mut out = [0u8; 32];
        let r = unsafe {
            openssl_sys::EVP_PKEY_get_raw_public_key(
                self.public_key.as_ptr(),
                out.as_mut_ptr(),
                &mut out.len(),
            )
        };
        if r == 0 {
            return Err(ErrorStack::get().into());
        }
        Ok(out)
    }
}

impl PublicKeyToJwk for Ed25519PublicKey {
    fn public_key_to_jwk(&self) -> Result<Jwk> {
        let bytes: [u8; 32] = self.to_bytes()?;
        Ok(Jwk {
            kty: "OKP".into(),
            crv: Some("Ed25519".into()),
            x: Some(base64::encode_config(&bytes, url_safe_trailing_bits())),
            ..Jwk::default()
        })
    }
}

impl SigningKey for Ed25519PrivateKey {
    fn sign(&self, v: &[u8]) -> Result<SmallVec<[u8; 64]>> {
        let mut signer = Signer::new_without_digest(self.private_key.as_ref())?;

        let mut out = [0u8; 64];

        signer.sign_oneshot(&mut out, v)?;

        Ok(out.into())
    }

    fn alg(&self) -> &'static str {
        "EdDSA"
    }
}

impl VerificationKey for Ed25519PrivateKey {
    fn verify(&self, v: &[u8], sig: &[u8], alg: &str) -> Result<()> {
        if alg != "EdDSA" {
            return Err(Error::VerificationError);
        }

        let mut verifier = Verifier::new_without_digest(self.private_key.as_ref())?;
        if verifier.verify_oneshot(sig, v)? {
            Ok(())
        } else {
            Err(Error::VerificationError)
        }
    }
}

impl VerificationKey for Ed25519PublicKey {
    fn verify(&self, v: &[u8], sig: &[u8], alg: &str) -> Result<()> {
        if alg != "EdDSA" {
            return Err(Error::VerificationError);
        }

        let mut verifier = Verifier::new_without_digest(self.public_key.as_ref())?;
        if verifier.verify_oneshot(sig, v)? {
            Ok(())
        } else {
            Err(Error::VerificationError)
        }
    }
}

#[cfg(test)]
mod tests {
    use openssl::{
        ec::{EcGroup, EcKey},
        nid::Nid,
    };

    use crate::{rsa::RsaAlgorithm, SomePrivateKey};

    use super::*;

    #[test]
    fn conversion() -> Result<()> {
        let k = Ed25519PrivateKey::generate()?;

        {
            let bytes = k.private_key_bytes()?;
            let k1 = Ed25519PrivateKey::from_bytes(&bytes)?;
            let bytes1 = k1.private_key_bytes()?;
            assert_eq!(bytes, bytes1);
        }

        let pem = k.private_key_to_pem_pkcs8()?;
        Ed25519PrivateKey::from_pem(pem.as_bytes())?;

        let secp256k1_k = EcKey::generate(EcGroup::from_curve_name(Nid::SECP256K1)?.as_ref())?;
        let secp256k1_k_pem = secp256k1_k.private_key_to_pem()?;
        let secp256k1_k_pub_pem = secp256k1_k.public_key_to_pem()?;
        assert!(Ed25519PrivateKey::from_pem(&secp256k1_k_pem).is_err());
        assert!(Ed25519PublicKey::from_pem(&secp256k1_k_pub_pem).is_err());

        let pk_pem = k.public_key_to_pem()?;

        let pk = Ed25519PublicKey::from_pem(pk_pem.as_bytes())?;

        println!("k: {:?}, pk: {:?}", k, pk);

        let pk_pem1 = pk.to_pem()?;

        assert_eq!(pk_pem, pk_pem1);

        if let SomePrivateKey::Ed25519(k1) = k
            .private_key_to_jwk()?
            .to_signing_key(RsaAlgorithm::PS256)?
        {
            assert!(k.private_key.public_eq(k1.private_key.as_ref()));
        } else {
            panic!("expected ed25519 private key");
        }

        k.public_key_to_jwk()?.to_verification_key()?;
        pk.public_key_to_jwk()?.to_verification_key()?;

        Ok(())
    }

    #[test]
    fn sign_verify() -> Result<()> {
        let k = Ed25519PrivateKey::generate()?;
        let pk = Ed25519PublicKey::from_pem(k.public_key_to_pem()?.as_bytes())?;
        let sig = k.sign(b"...")?;
        assert!(k.verify(b"...", &sig, "EdDSA").is_ok());
        assert!(pk.verify(b"...", &sig, "EdDSA").is_ok());
        assert!(pk.verify(b"....", &sig, "EdDSA").is_err());
        assert!(pk.verify(b"...", &sig, "WRONG ALG").is_err());
        assert!(pk.verify(b"...", &sig[..63], "EdDSA").is_err());
        Ok(())
    }
}
