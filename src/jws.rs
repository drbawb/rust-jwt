//! JSON Web Signature
//!
//! Protects the header and payload against changes, but performs no
//! encryption.

use std::str;
use std::error::{Error, FromError};

use serialize::base64;
use serialize::base64::{ToBase64, FromBase64};
use serialize::json;

use claims::Claims;
use util::safe_cmp;

fn encode_generic(claims: &Claims, header: String, sign: |&[u8]| -> Vec<u8>) -> String {
    let mut res = header;
    res.push('.');
    res.push_str(&*claims.to_base64(base64::URL_SAFE));
    let sig = (&*sign(res.as_bytes())).to_base64(base64::URL_SAFE);
    res.push('.');
    res.push_str(&*sig);
    res
}

#[deriving(Show, Eq, PartialEq)]
pub enum DecodeError {
    Malformed,
    InvalidSignature,
}

impl Error for DecodeError {
    fn description(&self) -> &str {
        match *self {
            DecodeError::Malformed => "not in JWS Compact Serialization format",
            DecodeError::InvalidSignature => "signature validation failed",
        }
    }
}

impl FromError<base64::FromBase64Error> for DecodeError {
    fn from_error(_: base64::FromBase64Error) -> DecodeError { DecodeError::Malformed }
}

impl FromError<json::BuilderError> for DecodeError {
    fn from_error(_: json::BuilderError) -> DecodeError { DecodeError::Malformed }
}

macro_rules! try_option (
    ($expr:expr, $err:expr) => (
        match $expr {
            Some(val) => val,
            None => return Err($err),
        }
    )
);

fn decode_generic(input: &str,
                  sign: |header64: &[u8], payload64: &[u8]| -> Vec<u8>)
                  -> Result<Claims, DecodeError> {
    let parts: Vec<&str> = input.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err(DecodeError::Malformed);
    }
    let sig_bytes = try!(parts[2].from_base64());
    let computed_sig = sign(parts[0].as_bytes(), parts[1].as_bytes());
    if !safe_cmp(&*sig_bytes, &*computed_sig) {
        return Err(DecodeError::InvalidSignature);
    }
    let payload_bytes = try!(parts[1].from_base64());
    let payload_str = try_option!(str::from_utf8(&*payload_bytes), DecodeError::Malformed);
    let payload = try!(json::from_str(payload_str));
    let claims = Claims { raw: try_option!(payload.as_object(), DecodeError::Malformed).clone() };
    Ok(claims)
}

pub mod hs256 {
    //! Signing with HMAC-SHA256

    use openssl::crypto;

    use claims::Claims;
    use jws::{encode_generic, decode_generic, DecodeError};

    // {"alg":"HS256","typ":"JWT"}
    static HEADER: &'static str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";

    /// Encode a set of claims and sign with HMAC-SHA256.
    pub fn encode(claims: &Claims, key: &[u8]) -> String {
        encode_generic(claims, HEADER.to_string(), |input| {
            let mut hmac = crypto::hmac::HMAC(crypto::hash::HashType::SHA256, key);
            hmac.update(input);
            hmac.finalize()
        })
    }

    /// Decode a JWT signed with HMAC-SHA256.
    pub fn decode(input: &str, key: &[u8]) -> Result<Claims, DecodeError> {
        decode_generic(input, |header64: &[u8], payload64: &[u8]| {
            let mut hmac = crypto::hmac::HMAC(crypto::hash::HashType::SHA256, key);
            hmac.update(header64);
            hmac.update(b".");
            hmac.update(payload64);
            hmac.finalize()
        })
    }

    #[cfg(test)]
    mod test {
        use claims::Claims;
        use super::{encode, decode};
        use jws::DecodeError;

        // header:  {"alg":"HS256","typ":"JWT"}
        // payload: {"com.example.my":"value","sub":"urn:someone"}
        // key:     b"secret"
        static TEST_TOKEN: &'static str =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
             eyJjb20uZXhhbXBsZS5teSI6InZhbHVlIiwic3ViIjoidXJuOnNvbWVvbmUifQ.\
             DImW_zVyj4FVU2hp_cgJCxphuJdkkSqPtGHAHTcCUe8";

        static INVALID_TOKEN: &'static str =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
             eyJjb20uZXhhbXBsZS5teSI6InZhbHVlIiwic3ViIjoidXJuOnNvbWVvbmUifQ.\
             AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

        #[test]
        fn test_encode() {
            let mut claims = Claims::new();
            claims.insert_unsafe("com.example.my", "value".to_string());
            claims.insert_unsafe("sub", "urn:someone".to_string());
            let jwt = encode(&claims, b"secret");
            assert_eq!(TEST_TOKEN, jwt.as_slice());
        }

        #[test]
        fn test_decode() {
            let claims = decode(TEST_TOKEN, b"secret").unwrap();
            assert_eq!(2, claims.raw.len());
			assert_eq!(Some("value"), claims.get("com.example.my").and_then(|v| v.as_string()));
            assert_eq!(Some("value"), claims.raw["com.example.my".to_string()].as_string());
            assert_eq!(Some("urn:someone"), claims.sub());
        }

        #[test]
        fn test_signature() {
            assert!(match decode(INVALID_TOKEN, b"secret") {
                Ok(_) => false,
                Err(err) => err == DecodeError::InvalidSignature,
            });
        }

        #[test]
        fn test_e2e() {
            let mut claims = Claims::new();
            claims.insert_unsafe("com.example.my", "value".to_string());
            claims.insert_unsafe("sub", "urn:someone".to_string());
            let jwt = encode(&claims, b"secret");
            let decoded_claims = decode(&*jwt, b"secret").unwrap();
            assert_eq!(claims, decoded_claims);
        }
    }
}
