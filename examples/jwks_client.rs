#[cfg(feature = "remote-jwks")]
#[tokio::main]
async fn main() -> jwtk::Result<()> {
    use std::time::Duration;

    use jwtk::jwk::RemoteJwksVerifier;
    use serde::Deserialize;
    use serde_json::{Map, Value};

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
    );
    let c = j.verify::<Map<String, Value>>(&v.token).await?;

    println!("{}", serde_json::to_string(c.claims())?);

    Ok(())
}

#[cfg(not(feature = "remote-jwks"))]
fn main() {}
