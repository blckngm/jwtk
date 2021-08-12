#![feature(test)]

use std::time::Duration;

use jwtk::{
    ecdsa::{EcdsaAlgorithm, EcdsaPrivateKey},
    eddsa::Ed25519PrivateKey,
    hmac::{HmacAlgorithm, HmacKey},
    rsa::RsaPrivateKey,
    HeaderAndClaims,
};

extern crate test;

#[bench]
fn bench_sig_es256(b: &mut test::Bencher) {
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

#[bench]
fn bench_sig_rs256(b: &mut test::Bencher) {
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

#[bench]
fn bench_sig_ps256(b: &mut test::Bencher) {
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

#[bench]
fn bench_sig_hs256(b: &mut test::Bencher) {
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

#[bench]
fn bench_sig_ed25519(b: &mut test::Bencher) {
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
