//! A JWKS server and token issuer.
//!
//! Reads private key fro `key.pem` (supports RSA, EC and Ed25519 keys). For
//! RSA, you can set the RSA_ALGO env var to use algorithms other than RS256.
//!
//! Jwks will be available at http://127.0.0.1:3000/jwks
//!
//! Tokens will be issued at http://127.0.0.1:3000/token

use axum::{
    prelude::*,
    response::{IntoResponse, Json},
    AddExtensionLayer,
};
use jwtk::{
    jwk::{JwkSet, WithKid},
    rsa::RsaAlgorithm,
    sign, HeaderAndClaims, PublicKeyToJwk, SomePrivateKey,
};
use std::{net::Ipv4Addr, sync::Arc, time::Duration};

struct State {
    k: WithKid<SomePrivateKey>,
    jwks: JwkSet,
}

async fn jwks_handler(state: extract::Extension<Arc<State>>) -> impl IntoResponse {
    Json(&state.jwks).into_response()
}

async fn token_handler(state: extract::Extension<Arc<State>>) -> impl IntoResponse {
    let mut token = HeaderAndClaims::new_dynamic();
    token
        .set_iss("me")
        .set_sub("you")
        .add_aud("them")
        .set_exp_from_now(Duration::from_secs(300))
        .insert("foo", "bar");
    let token = sign(&mut token, &state.k).unwrap();
    Json(serde_json::json!({
        "token": token,
    }))
}

#[tokio::main]
async fn main() -> jwtk::Result<()> {
    let k = std::fs::read("key.pem")?;

    let k = SomePrivateKey::from_pem(
        &k,
        match std::env::var("RSA_ALGO").as_deref() {
            Ok(alg) => RsaAlgorithm::from_name(alg)?,
            _ => RsaAlgorithm::RS256,
        },
    )?;
    println!("using key {:?}", k);

    let k = WithKid::new("my key".into(), k);

    let k_public_jwk = k.public_key_to_jwk()?;
    let jwks = JwkSet {
        keys: vec![k_public_jwk],
    };

    let state = Arc::new(State { k, jwks });

    let app = route("/jwks", get(jwks_handler))
        .route("/token", get(token_handler))
        .layer(AddExtensionLayer::new(state));

    axum::Server::bind(&(Ipv4Addr::from(0), 3000).into())
        .serve(app.into_make_service())
        .await
        .unwrap();

    Ok(())
}
