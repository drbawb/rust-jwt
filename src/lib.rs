//! Implementation of JSON Web Tokens.
//!
//! # Example
//!
//! ```rust
//! extern crate jwt;
//! use jwt::Claims;
//! use jwt::jws::hs256::{encode, decode};
//! 
//! fn main() {
//!     let mut claims = Claims::new();
//!     claims.insert_unsafe("com.example.my-claim", "value".to_string());
//!     let token = encode(&claims, b"secret");
//!     let decoded = decode(&*token, b"secret").unwrap();
//!     assert_eq!(claims, decoded);
//!     println!("ok");
//! }
//! ```

#![crate_name = "jwt"]
#![license = "MIT"]
#![experimental]

#![feature(macro_rules)]

extern crate time;
extern crate serialize;
extern crate openssl;

pub use claims::Claims;

mod claims;
pub mod jws;

mod util {
    pub fn safe_cmp(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() { return false; }
        let mut r: u8 = 0;
        for i in range(0, a.len()) {
            r |= a[i] ^ b[i];
        }
        r == 0
    }
}
