JWT signing (JWS) and verification, with first class JWK and JWK Set (JWKS)
support.

## Algorithms

* RS256, RS384, RS512, PS256, PS384, PS512 (verification: `aws-lc` or `openssl`; signing: `openssl`)
* HS256, HS384, HS512 (feature: `openssl`)
* ES256, ES384, ES512, ES256K (feature: `openssl`)
* Ed25519 (feature: `openssl`)

Supports `exp` and `nbf` validations. (Other validations will not be supported,
because they are mostly application specific and can be easily implemented by
applications.)

Supports converting public/private keys to/from JWK. PEM support is available
when the `openssl` feature is enabled. Supports working with generic keys
(where the algorithm is determined at runtime), i.e.
`SomePrivateKey`/`SomePublicKey`.

## Features

| Feature | Default | Description |
|---------|---------|-------------|
| `aws-lc` | Yes | RSA signature verification via [aws-lc-rs](https://github.com/aws/aws-lc-rs). |
| `openssl` | No | Full algorithm support (RSA signing & verification, HMAC, ECDSA, EdDSA) via OpenSSL. When enabled, RSA uses OpenSSL instead of aws-lc-rs. |
| `remote-jwks` | Yes | `RemoteJwksVerifier` for fetching and caching remote JWK Sets. |

With the default features (`aws-lc` + `remote-jwks`), RSA JWT verification
works out of the box.

## Examples

See the `examples` folder for usage examples.
