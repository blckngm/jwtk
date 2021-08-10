use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey},
    ecdsa::EcdsaSig,
    hash::MessageDigest,
    nid::Nid,
    pkey::{HasPublic, PKey, PKeyRef, Private, Public},
    sign::{Signer, Verifier},
};
use smallvec::SmallVec;

use crate::{
    jwk::{Jwk, PublicKeyToJwk},
    url_safe_trailing_bits, Error, Result, SigningKey, VerificationKey,
};

#[derive(Debug)]
pub struct ES256PrivateKey(pub(crate) PKey<Private>);

impl ES256PrivateKey {
    pub fn generate() -> Result<Self> {
        let ec_key = EcKey::generate(EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?.as_ref())?;
        Ok(Self(PKey::from_ec_key(ec_key)?))
    }

    pub fn from_pem(pem: &[u8]) -> Result<Self> {
        let pk = PKey::private_key_from_pem(pem)?;
        if pk.ec_key()?.group().curve_name() != Some(Nid::X9_62_PRIME256V1) {
            return Err(Error::UnsupportedOrInvalidKey);
        }
        pk.ec_key()?.check_key()?;
        Ok(Self(pk))
    }

    pub fn private_key_to_pem_pkcs8(&self) -> Result<Vec<u8>> {
        Ok(self.0.private_key_to_pem_pkcs8()?)
    }

    pub fn public_key_pem(&self) -> Result<Vec<u8>> {
        Ok(self.0.public_key_to_pem()?)
    }

    /// (x, y)
    pub fn coordinates(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut ctx = BigNumContext::new()?;
        let mut x = BigNum::new()?;
        let mut y = BigNum::new()?;
        let ec = self.0.ec_key()?;
        ec.public_key()
            .affine_coordinates(ec.group(), &mut x, &mut y, &mut ctx)?;
        Ok((x.to_vec(), y.to_vec()))
    }
}

#[derive(Debug)]
pub struct ES256PublicKey(pub(crate) PKey<Public>);

impl ES256PublicKey {
    pub fn from_pem(pem: &[u8]) -> Result<Self> {
        let pk = PKey::public_key_from_pem(pem)?;
        if pk.ec_key()?.group().curve_name() != Some(Nid::X9_62_PRIME256V1) {
            Err(Error::UnsupportedOrInvalidKey)
        } else {
            Ok(Self(pk))
        }
    }

    pub fn to_pem(&self) -> Result<Vec<u8>> {
        Ok(self.0.public_key_to_pem()?)
    }

    /// (x, y)
    pub fn coordinates(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut ctx = BigNumContext::new()?;
        let mut x = BigNum::new()?;
        let mut y = BigNum::new()?;
        let ec = self.0.ec_key()?;
        ec.public_key()
            .affine_coordinates(ec.group(), &mut x, &mut y, &mut ctx)?;
        Ok((x.to_vec(), y.to_vec()))
    }

    pub fn from_coordinates(x: &[u8], y: &[u8]) -> Result<Self> {
        let pk = EcKey::from_public_key_affine_coordinates(
            EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?.as_ref(),
            BigNum::from_slice(x)?.as_ref(),
            BigNum::from_slice(y)?.as_ref(),
        )?;
        pk.check_key()?;
        Ok(Self(PKey::from_ec_key(pk)?))
    }
}

impl SigningKey for ES256PrivateKey {
    fn sign(&self, v: &[u8]) -> Result<SmallVec<[u8; 64]>> {
        let mut signer = Signer::new(MessageDigest::sha256(), self.0.as_ref())?;
        signer.update(v)?;
        let sig_der = signer.sign_to_vec()?;

        // Convert from DER to fixed length.
        let sig = EcdsaSig::from_der(&sig_der)?;

        let mut out = [0u8; 64];

        let r = sig.r().to_vec();
        let s = sig.s().to_vec();

        out[(32 - r.len())..32].copy_from_slice(&r);
        out[(64 - s.len())..64].copy_from_slice(&s);

        Ok(out.into())
    }

    fn alg(&self) -> &'static str {
        "ES256"
    }
}

fn es256_verify<T: HasPublic>(k: &PKeyRef<T>, v: &[u8], sig: &[u8]) -> Result<()> {
    if sig.len() != 64 {
        return Err(Error::VerificationError);
    }
    let r = &sig[sig.iter().position(|&x| x != 0).unwrap_or(31)..32];
    let mut s = &sig[32..64];
    s = &s[s.iter().position(|&x| x != 0).unwrap_or(31)..];

    let sig = EcdsaSig::from_private_components(BigNum::from_slice(r)?, BigNum::from_slice(s)?)?;
    let der = sig.to_der()?;

    let mut verifier = Verifier::new(MessageDigest::sha256(), k)?;
    if verifier.verify_oneshot(&der, v)? {
        Ok(())
    } else {
        Err(Error::VerificationError)
    }
}

impl VerificationKey for ES256PrivateKey {
    fn verify(&self, v: &[u8], sig: &[u8]) -> Result<()> {
        es256_verify(self.0.as_ref(), v, sig)
    }

    #[inline]
    fn alg(&self) -> &'static str {
        "ES256"
    }
}

impl VerificationKey for ES256PublicKey {
    fn verify(&self, v: &[u8], sig: &[u8]) -> Result<()> {
        es256_verify(self.0.as_ref(), v, sig)
    }

    #[inline]
    fn alg(&self) -> &'static str {
        "ES256"
    }
}

impl PublicKeyToJwk for ES256PrivateKey {
    fn to_jwk(&self) -> Result<Jwk> {
        let (x, y) = self.coordinates()?;
        Ok(Jwk {
            kty: "EC".into(),
            use_: Some("sig".into()),
            alg: Some("ES256".into()),
            crv: Some("P-256".into()),
            x: Some(base64::encode_config(&x, url_safe_trailing_bits())),
            y: Some(base64::encode_config(&y, url_safe_trailing_bits())),
            ..Default::default()
        })
    }
}

impl PublicKeyToJwk for ES256PublicKey {
    fn to_jwk(&self) -> Result<Jwk> {
        let (x, y) = self.coordinates()?;
        Ok(Jwk {
            kty: "EC".into(),
            use_: Some("sig".into()),
            alg: Some("ES256".into()),
            crv: Some("P-256".into()),
            x: Some(base64::encode_config(&x, url_safe_trailing_bits())),
            y: Some(base64::encode_config(&y, url_safe_trailing_bits())),
            ..Default::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversion() -> Result<()> {
        let k = ES256PrivateKey::generate()?;
        let pem = k.private_key_to_pem_pkcs8()?;
        ES256PrivateKey::from_pem(&pem)?;

        let secp256k1_k = EcKey::generate(EcGroup::from_curve_name(Nid::SECP256K1)?.as_ref())?;
        let secp256k1_k_pem = secp256k1_k.private_key_to_pem()?;
        let secp256k1_k_pub_pem = secp256k1_k.public_key_to_pem()?;
        assert!(ES256PrivateKey::from_pem(&secp256k1_k_pem).is_err());
        assert!(ES256PublicKey::from_pem(&secp256k1_k_pub_pem).is_err());

        // Should be able to handle BEGIN EC PRIVATE KEY as well.
        let ec_pem = k.0.ec_key()?.private_key_to_pem()?;
        assert!(std::str::from_utf8(&ec_pem)
            .unwrap()
            .contains("BEGIN EC PRIVATE KEY"));
        ES256PrivateKey::from_pem(&ec_pem)?;

        let pk_pem = k.public_key_pem()?;

        let pk = ES256PublicKey::from_pem(&pk_pem)?;

        println!("k: {:?}, pk: {:?}", k, pk);

        let pk_pem1 = pk.to_pem()?;

        assert_eq!(pk_pem, pk_pem1);

        let (x, y) = k.coordinates()?;
        let (x1, y1) = pk.coordinates()?;

        assert_eq!((&x, &y), (&x1, &y1));

        ES256PublicKey::from_coordinates(&x, &y)?;

        k.to_jwk()?.to_verification_key()?;
        pk.to_jwk()?.to_verification_key()?;

        Ok(())
    }

    #[test]
    fn sign_verify() -> Result<()> {
        let k = ES256PrivateKey::generate()?;
        let (x, y) = k.coordinates()?;
        let pk = ES256PublicKey::from_coordinates(&x, &y)?;
        let sig = k.sign(b"...")?;
        assert!(pk.verify(b"...", &sig).is_ok());
        assert!(pk.verify(b"....", &sig).is_err());
        assert!(pk.verify(b"....", &sig[..63]).is_err());
        Ok(())
    }
}
