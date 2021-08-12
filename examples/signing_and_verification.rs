use jwtk::{
    ecdsa::{EcdsaAlgorithm, EcdsaPrivateKey, EcdsaPublicKey},
    sign, verify, HeaderAndClaims,
};
use serde_json::{Map, Value};
use std::time::Duration;

fn main() -> jwtk::Result<()> {
    let k = EcdsaPrivateKey::generate(EcdsaAlgorithm::ES256)?;

    let pem = k.public_key_to_pem()?;
    println!("Public Key:\n{}", std::str::from_utf8(&pem).unwrap());
    let pk = EcdsaPublicKey::from_pem(&pem)?;

    let token = sign(
        HeaderAndClaims::new_dynamic()
            .set_exp_from_now(Duration::from_secs(300))
            .set_iss("me")
            .insert("foo", "bar"),
        &k,
    )?;
    println!("token:\n{}", token);

    let verified = verify::<Map<String, Value>>(&token, &pk)?;
    assert_eq!(verified.claims().extra["foo"], "bar");

    Ok(())
}
