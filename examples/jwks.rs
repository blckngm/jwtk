/// A JWKS/JWT server.
use axum::{
    prelude::*,
    response::{IntoResponse, Json},
    AddExtensionLayer,
};
use jwtk::{
    es256::ES256PrivateKey,
    jwk::{JwkSet, PublicKeyToJwk},
    sign, HeaderAndClaims,
};
use std::{net::Ipv4Addr, sync::Arc, time::Duration};

struct State {
    k: ES256PrivateKey,
    kid: &'static str,
    jwks: JwkSet,
}

async fn jwks_handler(state: extract::Extension<Arc<State>>) -> impl IntoResponse {
    Json(&state.jwks).into_response()
}

async fn token_handler(state: extract::Extension<Arc<State>>) -> impl IntoResponse {
    let mut token = HeaderAndClaims::new_dynamic();
    token
        .set_kid(state.kid)
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
    let kid = "my key";
    let k = ES256PrivateKey::generate()?;

    let mut k_public_jwk = k.to_jwk()?;
    k_public_jwk.kid = Some(kid.into());
    let jwks = JwkSet {
        keys: vec![k_public_jwk],
    };

    let state = Arc::new(State { k, kid, jwks });

    let app = route("/jwks", get(jwks_handler))
        .route("/token", get(token_handler))
        .layer(AddExtensionLayer::new(state));

    axum::Server::bind(&(Ipv4Addr::from(0), 3000).into())
        .serve(app.into_make_service())
        .await
        .unwrap();

    Ok(())
}
