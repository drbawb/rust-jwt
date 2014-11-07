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
