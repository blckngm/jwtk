use jwtk::{
    es256::{ES256PrivateKey, ES256PublicKey},
    sign, verify, HeaderAndClaims,
};
use serde_json::{Map, Value};
use std::time::Duration;

fn main() -> jwtk::Result<()> {
    let k = ES256PrivateKey::generate()?;
    let token = sign(
        HeaderAndClaims::new_dynamic()
            .set_exp_from_now(Duration::from_secs(300))
            .set_iss("me")
            .insert("foo", "bar"),
        &k,
    )?;
    println!("token:\n{}\n", token);

    let pem = k.public_key_pem()?;
    println!("Public Key:\n{}", std::str::from_utf8(&pem).unwrap());
    let pk = ES256PublicKey::from_pem(&pem)?;

    let verified = verify::<Map<String, Value>>(&token, &pk)?;
    assert_eq!(verified.claims().extra["foo"], "bar");

    Ok(())
}
