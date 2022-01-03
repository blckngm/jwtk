JWT signing (JWS) and verification, with first class JWK and JWK Set (JWKS)
support.

Supports almost all JWS algorithms:

* HS256, HS384, HS512
* Ed25519
* ES256, ES384, ES512, ES256K
* RS256, RS384, RS512
* PS256, PS384, PS512

Supports `exp` and `nbf` validations. (Other validations will not be supported,
because they are mostly application specific and can be easily implemented by
applications.)

Supports converting public/private keys to/from PEM/JWK. Supports working with
generic keys (where the algorithm is determined at runtime), i.e.
`SomePrivateKey`/`SomePublicKey`.

Uses good old openssl for crypto.

See the `examples` folder for some examples.
