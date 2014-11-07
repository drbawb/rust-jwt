rust-jwt
========

[![Build Status](https://travis-ci.org/stygstra/rust-jwt.svg?branch=master)](https://travis-ci.org/stygstra/rust-jwt)
Rust implementation of JSON Web Tokens

Usable, but not production ready. Hasn't been audited for security and
the API will change.

Usage
-----

Add this to your Cargo.toml:

    [dependencies.jwt]

    git = "https://github.com/stygstra/rust-jwt"

Example:

    extern crate jwt;
    use jwt::Claims;
    use jwt::jws::hs256::{encode, decode};

    fn main() {
        let mut claims = Claims::new();
        claims.insert_unsafe("com.example.my-claim", "value".to_string());
        let token = encode(&claims, b"secret");
        let decoded = decode(&*token, b"secret").unwrap();
        assert_eq!(claims, decoded);
        println!("ok");
    }

Todo
----

-   [More algorithms](https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-36#section-3.1) (at least RS256 and ES256)
-   [Validate `crit` header](https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-36#section-4.1.11)
-   [Validate registered claims](https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-30#section-4.1)
-   [JWE](https://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-36)
-   Improve API

Documentation
-------------

[View documentation](http://www.rust-ci.org/stygstra/rust-jwt/doc/jwt/).
