#![feature(test)]

use std::time::Duration;

use jwtk::HeaderAndClaims;

extern crate test;

#[cfg(feature = "openssl")]
#[bench]
fn bench_sig_es256(b: &mut test::Bencher) {
    use jwtk::ecdsa::{EcdsaAlgorithm, EcdsaPrivateKey};

    let k = EcdsaPrivateKey::generate(EcdsaAlgorithm::ES256).unwrap();

    b.iter(|| {
        jwtk::sign(
            HeaderAndClaims::with_claims(())
                .set_exp_from_now(Duration::from_secs(60))
                .set_sub("you")
                .add_aud("them")
                .set_iat_now(),
            &k,
        )
        .unwrap()
    });
}

#[cfg(any(feature = "rsa", feature = "openssl"))]
#[bench]
fn bench_sig_rs256(b: &mut test::Bencher) {
    use jwtk::rsa::RsaPrivateKey;

    let k = RsaPrivateKey::generate(2048, jwtk::rsa::RsaAlgorithm::RS256).unwrap();

    b.iter(|| {
        jwtk::sign(
            HeaderAndClaims::with_claims(())
                .set_exp_from_now(Duration::from_secs(60))
                .set_sub("you")
                .add_aud("them")
                .set_iat_now(),
            &k,
        )
        .unwrap()
    });
}

#[cfg(any(feature = "rsa", feature = "openssl"))]
#[bench]
fn bench_sig_ps256(b: &mut test::Bencher) {
    use jwtk::rsa::RsaPrivateKey;

    let k = RsaPrivateKey::generate(2048, jwtk::rsa::RsaAlgorithm::PS256).unwrap();

    b.iter(|| {
        jwtk::sign(
            HeaderAndClaims::with_claims(())
                .set_exp_from_now(Duration::from_secs(60))
                .set_sub("you")
                .add_aud("them")
                .set_iat_now(),
            &k,
        )
        .unwrap()
    });
}

#[cfg(feature = "openssl")]
#[bench]
fn bench_sig_hs256(b: &mut test::Bencher) {
    use jwtk::hmac::{HmacAlgorithm, HmacKey};

    let k = HmacKey::generate(HmacAlgorithm::HS256).unwrap();

    b.iter(|| {
        jwtk::sign(
            HeaderAndClaims::with_claims(())
                .set_exp_from_now(Duration::from_secs(60))
                .set_sub("you")
                .add_aud("them")
                .set_iat_now(),
            &k,
        )
        .unwrap()
    });
}

#[cfg(feature = "openssl")]
#[bench]
fn bench_sig_ed25519(b: &mut test::Bencher) {
    use jwtk::eddsa::Ed25519PrivateKey;

    let k = Ed25519PrivateKey::generate().unwrap();

    b.iter(|| {
        jwtk::sign(
            HeaderAndClaims::with_claims(())
                .set_exp_from_now(Duration::from_secs(60))
                .set_sub("you")
                .add_aud("them")
                .set_iat_now(),
            &k,
        )
        .unwrap()
    });
}
