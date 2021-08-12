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
    jwk::Jwk, url_safe_trailing_bits, Error, PublicKeyToJwk, Result, SigningKey, VerificationKey,
};

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcdsaAlgorithm {
    ES256,
    // https://datatracker.ietf.org/doc/html/draft-ietf-cose-webauthn-algorithms-04
    ES256K,
    ES384,
    ES512,
}

impl EcdsaAlgorithm {
    fn curve(self) -> Nid {
        use EcdsaAlgorithm::*;
        match self {
            ES256 => Nid::X9_62_PRIME256V1,
            ES256K => Nid::SECP256K1,
            ES384 => Nid::SECP384R1,
            ES512 => Nid::SECP521R1,
        }
    }

    fn from_curve(curve: Nid) -> Result<Self> {
        use EcdsaAlgorithm::*;
        Ok(match curve {
            Nid::X9_62_PRIME256V1 => ES256,
            Nid::SECP256K1 => ES256K,
            Nid::SECP384R1 => ES384,
            Nid::SECP521R1 => ES512,
            _ => return Err(Error::UnsupportedOrInvalidKey),
        })
    }

    fn digest(self) -> MessageDigest {
        use EcdsaAlgorithm::*;
        match self {
            ES256 | ES256K => MessageDigest::sha256(),
            ES384 => MessageDigest::sha384(),
            ES512 => MessageDigest::sha512(),
        }
    }

    fn name(self) -> &'static str {
        use EcdsaAlgorithm::*;
        match self {
            ES256 => "ES256",
            ES256K => "ES256K",
            ES384 => "ES384",
            ES512 => "ES512",
        }
    }

    fn curve_name(self) -> &'static str {
        use EcdsaAlgorithm::*;
        match self {
            ES256 => "P-256",
            ES256K => "secp256k1",
            ES384 => "P-384",
            ES512 => "P-521",
        }
    }

    pub(crate) fn from_curve_name(name: &str) -> Result<Self> {
        use EcdsaAlgorithm::*;
        Ok(match name {
            "P-256" => ES256,
            "secp256k1" => ES256K,
            "P-384" => ES384,
            "P-521" => ES512,
            _ => return Err(Error::UnsupportedOrInvalidKey),
        })
    }

    // Signature length. Also == 2 * r == 2 * s == 2 * x == 2 * y.
    fn len(self) -> usize {
        use EcdsaAlgorithm::*;
        match self {
            ES256 | ES256K => 64,
            ES384 => 96,
            ES512 => 132,
        }
    }
}

#[derive(Debug)]
pub struct EcdsaPrivateKey {
    private_key: PKey<Private>,
    algorithm: EcdsaAlgorithm,
}

impl EcdsaPrivateKey {
    pub fn generate(algorithm: EcdsaAlgorithm) -> Result<Self> {
        let ec_key = EcKey::generate(EcGroup::from_curve_name(algorithm.curve())?.as_ref())?;
        Ok(Self {
            private_key: PKey::from_ec_key(ec_key)?,
            algorithm,
        })
    }

    pub(crate) fn from_pkey(pk: PKey<Private>) -> Result<Self> {
        pk.ec_key()?.check_key()?;
        let curve = pk
            .ec_key()?
            .group()
            .curve_name()
            .ok_or(Error::UnsupportedOrInvalidKey)?;
        let algorithm = EcdsaAlgorithm::from_curve(curve)?;

        Ok(Self {
            private_key: pk,
            algorithm,
        })
    }

    pub fn from_pem(pem: &[u8]) -> Result<Self> {
        let pk = PKey::private_key_from_pem(pem)?;
        Self::from_pkey(pk)
    }

    pub fn private_key_to_pem_pkcs8(&self) -> Result<Vec<u8>> {
        Ok(self.private_key.private_key_to_pem_pkcs8()?)
    }

    pub fn public_key_to_pem(&self) -> Result<Vec<u8>> {
        Ok(self.private_key.public_key_to_pem()?)
    }

    /// Public key X Y coordinates. Always padded to the full size.
    pub fn coordinates(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut ctx = BigNumContext::new()?;
        let mut x = BigNum::new()?;
        let mut y = BigNum::new()?;
        let ec = self.private_key.ec_key()?;
        ec.public_key()
            .affine_coordinates(ec.group(), &mut x, &mut y, &mut ctx)?;
        let (mut x, mut y) = (x.to_vec(), y.to_vec());
        pad_left(&mut x, self.algorithm.len() / 2);
        pad_left(&mut y, self.algorithm.len() / 2);
        Ok((x, y))
    }
}

impl PublicKeyToJwk for EcdsaPrivateKey {
    fn public_key_to_jwk(&self) -> Result<Jwk> {
        let (x, y) = self.coordinates()?;
        Ok(Jwk {
            kty: "EC".into(),
            use_: Some("sig".into()),
            crv: Some(self.algorithm.curve_name().into()),
            x: Some(base64::encode_config(&x, url_safe_trailing_bits())),
            y: Some(base64::encode_config(&y, url_safe_trailing_bits())),
            ..Default::default()
        })
    }
}

fn pad_left(v: &mut Vec<u8>, len: usize) {
    debug_assert!(v.len() <= len);
    if v.len() == len {
        return;
    }
    let old_len = v.len();
    v.resize(len, 0);
    v.copy_within(0..old_len, len - old_len);
    v[..(len - old_len)].fill(0);
}

#[cfg(test)]
#[test]
fn test_pad_left() {
    let mut v = vec![5, 6, 7];
    pad_left(&mut v, 3);
    assert_eq!(v, [5, 6, 7]);
    pad_left(&mut v, 8);
    assert_eq!(v, [0, 0, 0, 0, 0, 5, 6, 7]);
}

#[derive(Debug)]
pub struct EcdsaPublicKey {
    public_key: PKey<Public>,
    algorithm: EcdsaAlgorithm,
}

impl EcdsaPublicKey {
    pub(crate) fn from_pkey(pkey: PKey<Public>) -> Result<Self> {
        pkey.ec_key()?.check_key()?;

        let curve = pkey
            .ec_key()?
            .group()
            .curve_name()
            .ok_or(Error::UnsupportedOrInvalidKey)?;
        let algorithm = EcdsaAlgorithm::from_curve(curve)?;

        Ok(Self {
            public_key: pkey,
            algorithm,
        })
    }

    pub fn from_pem(pem: &[u8]) -> Result<Self> {
        let pk = PKey::public_key_from_pem(pem)?;
        Self::from_pkey(pk)
    }

    pub fn to_pem(&self) -> Result<Vec<u8>> {
        Ok(self.public_key.public_key_to_pem()?)
    }

    /// X Y coordinates. Always padded to the full size.
    pub fn coordinates(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut ctx = BigNumContext::new()?;
        let mut x = BigNum::new()?;
        let mut y = BigNum::new()?;
        let ec = self.public_key.ec_key()?;
        ec.public_key()
            .affine_coordinates(ec.group(), &mut x, &mut y, &mut ctx)?;
        let (mut x, mut y) = (x.to_vec(), y.to_vec());
        pad_left(&mut x, self.algorithm.len() / 2);
        pad_left(&mut y, self.algorithm.len() / 2);
        Ok((x, y))
    }

    pub fn from_coordinates(x: &[u8], y: &[u8], algorithm: EcdsaAlgorithm) -> Result<Self> {
        let k = EcKey::from_public_key_affine_coordinates(
            EcGroup::from_curve_name(algorithm.curve())?.as_ref(),
            BigNum::from_slice(x)?.as_ref(),
            BigNum::from_slice(y)?.as_ref(),
        )?;
        k.check_key()?;
        Ok(Self {
            public_key: PKey::from_ec_key(k)?,
            algorithm,
        })
    }
}

impl PublicKeyToJwk for EcdsaPublicKey {
    fn public_key_to_jwk(&self) -> Result<Jwk> {
        let (x, y) = self.coordinates()?;
        Ok(Jwk {
            kty: "EC".into(),
            use_: Some("sig".into()),
            crv: Some(self.algorithm.curve_name().into()),
            x: Some(base64::encode_config(&x, url_safe_trailing_bits())),
            y: Some(base64::encode_config(&y, url_safe_trailing_bits())),
            ..Default::default()
        })
    }
}

impl SigningKey for EcdsaPrivateKey {
    fn sign(&self, v: &[u8]) -> Result<SmallVec<[u8; 64]>> {
        let mut signer = Signer::new(self.algorithm.digest(), self.private_key.as_ref())?;
        signer.update(v)?;
        let sig_der = signer.sign_to_vec()?;

        // Convert from DER to fixed length.
        let sig = EcdsaSig::from_der(&sig_der)?;

        let mut out = smallvec::smallvec![0u8; self.algorithm.len()];

        let r = sig.r().to_vec();
        let s = sig.s().to_vec();

        let sig_len = self.algorithm.len();
        let half_len = sig_len / 2;

        out[(half_len - r.len())..half_len].copy_from_slice(&r);
        out[(sig_len - s.len())..].copy_from_slice(&s);

        Ok(out)
    }

    fn alg(&self) -> &'static str {
        self.algorithm.name()
    }
}

fn ecdsa_verify<T: HasPublic>(
    alg: EcdsaAlgorithm,
    k: &PKeyRef<T>,
    v: &[u8],
    sig: &[u8],
) -> Result<()> {
    if sig.len() != alg.len() {
        return Err(Error::VerificationError);
    }
    let half_len = alg.len() / 2;
    let r = &sig[sig.iter().position(|&x| x != 0).unwrap_or(half_len - 1)..half_len];
    let mut s = &sig[half_len..sig.len()];
    s = &s[s.iter().position(|&x| x != 0).unwrap_or(half_len - 1)..];

    let sig = EcdsaSig::from_private_components(BigNum::from_slice(r)?, BigNum::from_slice(s)?)?;
    let der = sig.to_der()?;

    let mut verifier = Verifier::new(alg.digest(), k)?;
    if verifier.verify_oneshot(&der, v)? {
        Ok(())
    } else {
        Err(Error::VerificationError)
    }
}

impl VerificationKey for EcdsaPrivateKey {
    fn verify(&self, v: &[u8], sig: &[u8], alg: &str) -> Result<()> {
        // ECDSA keys can handle only one algorithm.
        if alg != self.algorithm.name() {
            return Err(Error::VerificationError);
        }

        ecdsa_verify(self.algorithm, self.private_key.as_ref(), v, sig)
    }
}

impl VerificationKey for EcdsaPublicKey {
    fn verify(&self, v: &[u8], sig: &[u8], alg: &str) -> Result<()> {
        if alg != self.algorithm.name() {
            return Err(Error::VerificationError);
        }

        ecdsa_verify(self.algorithm, self.public_key.as_ref(), v, sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversion() -> Result<()> {
        let k = EcdsaPrivateKey::generate(EcdsaAlgorithm::ES256)?;
        let pem = k.private_key_to_pem_pkcs8()?;
        EcdsaPrivateKey::from_pem(&pem)?;

        let secp192k1_k = EcKey::generate(EcGroup::from_curve_name(Nid::SECP192K1)?.as_ref())?;
        let secp192k1_k_pem = secp192k1_k.private_key_to_pem()?;
        let secp192k1_k_pub_pem = secp192k1_k.public_key_to_pem()?;
        assert!(EcdsaPrivateKey::from_pem(&secp192k1_k_pem).is_err());
        assert!(EcdsaPublicKey::from_pem(&secp192k1_k_pub_pem).is_err());

        // Should be able to handle BEGIN EC PRIVATE KEY as well.
        let ec_pem = k.private_key.ec_key()?.private_key_to_pem()?;
        assert!(std::str::from_utf8(&ec_pem)
            .unwrap()
            .contains("BEGIN EC PRIVATE KEY"));
        EcdsaPrivateKey::from_pem(&ec_pem)?;

        let pk_pem = k.public_key_to_pem()?;

        let pk = EcdsaPublicKey::from_pem(&pk_pem)?;

        println!("k: {:?}, pk: {:?}", k, pk);

        let pk_pem1 = pk.to_pem()?;

        assert_eq!(pk_pem, pk_pem1);

        let (x, y) = k.coordinates()?;
        let (x1, y1) = pk.coordinates()?;

        assert_eq!((&x, &y), (&x1, &y1));

        EcdsaPublicKey::from_coordinates(&x, &y, EcdsaAlgorithm::ES256)?;

        k.public_key_to_jwk()?.to_verification_key()?;
        pk.public_key_to_jwk()?.to_verification_key()?;

        Ok(())
    }

    #[test]
    fn sign_verify() -> Result<()> {
        for alg in std::array::IntoIter::new([
            EcdsaAlgorithm::ES256,
            EcdsaAlgorithm::ES256K,
            EcdsaAlgorithm::ES384,
            EcdsaAlgorithm::ES512,
        ]) {
            let k = EcdsaPrivateKey::generate(alg)?;
            let (x, y) = k.coordinates()?;
            let pk = EcdsaPublicKey::from_coordinates(&x, &y, alg)?;
            let sig = k.sign(b"...")?;
            assert!(k.verify(b"...", &sig, alg.name()).is_ok());
            assert!(pk.verify(b"...", &sig, alg.name()).is_ok());
            assert!(pk.verify(b"....", &sig, alg.name()).is_err());
            assert!(pk.verify(b"...", &sig, "WRONG ALG").is_err());
            assert!(pk.verify(b"...", &sig[..63], alg.name()).is_err());
        }
        Ok(())
    }
}
