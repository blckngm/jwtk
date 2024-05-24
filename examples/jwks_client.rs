#[cfg(feature = "remote-jwks")]
#[tokio::main]
async fn main() -> jwtk::Result<()> {
    use jwtk::jwk::RemoteJwksVerifier;
    use serde::Deserialize;
    use serde_json::{Map, Value};
    use std::time::Duration;

    #[derive(Deserialize)]
    struct Token {
        token: String,
    }

    let v: Token = reqwest::get("http://127.0.0.1:3000/token")
        .await?
        .json()
        .await?;

    let j = RemoteJwksVerifier::new(
        "http://127.0.0.1:3000/jwks".into(),
        None,
        Duration::from_secs(300),
        None,
    );
    let c = j.verify::<Map<String, Value>>(&v.token).await?;

    println!("headers:\n{}", serde_json::to_string(c.header())?);
    println!("claims:\n{}", serde_json::to_string(c.claims())?);

    Ok(())
}

#[cfg(not(feature = "remote-jwks"))]
fn main() {}
