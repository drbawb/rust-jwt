use std::borrow::{BorrowFrom, ToOwned};
use std::collections::BTreeMap;

use rustc_serialize::base64;
use rustc_serialize::base64::ToBase64;
use rustc_serialize::json;
use rustc_serialize::json::ToJson;

/// A set of JWT claims.
#[derive(PartialEq, Show)]
pub struct Claims {
    /// Raw JSON contents of the claims. This may become private.
    pub raw: BTreeMap<String, json::Json>,
}

impl Claims {
    /// Create an empty claim set.
    pub fn new() -> Claims {
        Claims { raw: BTreeMap::new() }
    }

    /// Who issued the JWT.
    pub fn iss(&self) -> Option<&str> {
        self.raw.get(&"iss".to_string()).and_then(|iss| {
            iss.as_string().and_then(|iss| Some(iss))
        })
    }

    /// Subject of the JWT. Other claims are typically statements about
    /// the subject.
    pub fn sub(&self) -> Option<&str> {
        self.raw.get(&"sub".to_string()).and_then(|sub| {
            sub.as_string().and_then(|sub| Some(sub))
        })
    }

    /// List of recipients the JWT is intended for.
    pub fn aud(&self) -> Option<Vec<&str>> {
        self.raw.get(&"aud".to_string()).and_then(|aud| {
            aud.as_array().and_then(|aud| {
                let mut v: Vec<&str> = Vec::new();
                for member in aud.iter() {
                    match member.as_string() {
                        Some(s) => v.push(s),
                        None => return None,
                    }
                }
                Some(v)
            })
        })
    }

    /// Time after which the JWT is considered invalid (POSIX time).
    pub fn exp(&self) -> Option<f64> {
        self.raw.get(&"exp".to_string()).and_then(|exp| exp.as_f64())
    }

    /// Time before which the JWT is considered invalid (POSIX time).
    pub fn nbf(&self) -> Option<f64> {
        self.raw.get(&"nbf".to_string()).and_then(|nbf| nbf.as_f64())
    }

    /// Time the JWT was issued (POSIX time).
    pub fn iat(&self) -> Option<f64> {
        self.raw.get(&"iat".to_string()).and_then(|iat| iat.as_f64())
    }

    /// This is a unique identifier that may be used to prevent replays
    /// (JWT ID).
    pub fn jti(&self) -> Option<&str> {
        self.raw.get(&"jti".to_string()).and_then(|jti| {
            jti.as_string().and_then(|jti| Some(jti))
        })
    }

    /// Get the value of a claim.
    pub fn get<K: ?Sized+BorrowFrom<String>+Ord>(&self, key: &K) -> Option<&json::Json> {
        self.raw.get(key)
    }

    /// Add a (potentially unregistered) claim. Note that this can lead
    /// to an invalid JWT if the semantics of the claim don't match the
    /// JWT specification.
    pub fn insert_unsafe<V: ToJson>(&mut self, key: &str, value: V) {
        self.raw.insert(key.to_owned(), value.to_json());
    }

    /// Remove a claim.
    pub fn remove<K: ?Sized+BorrowFrom<String>+Ord>(&mut self, key: &K) -> Option<json::Json> {
        self.raw.remove(key)
    }
}

macro_rules! maybe_insert(
    ($src:ident.$var:ident, $dst:ident) => (
        match $src.$var {
            Some(ref x) => { $dst.insert(stringify!($var).to_string(), x.to_json()); },
            None => { },
        }
    );
);

impl ToJson for Claims {
    fn to_json(&self) -> json::Json {
        self.raw.to_json()
    }
}

impl ToBase64 for Claims {
    fn to_base64(&self, config: base64::Config) -> String {
        self.to_json().to_string().as_bytes().to_base64(config)
    }
}
