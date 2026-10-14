//! Reproduces every vector in `tests/vectors/signing.json`, which
//! website-devices' tests read a copy of.

use ed25519_dalek::SigningKey;
use mauvelyd::signing;
use serde_json::Value;

fn seed(hex: &str) -> [u8; 32] {
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    bytes.try_into().unwrap()
}

#[test]
fn signing_vectors() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/vectors/signing.json");
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(doc["format"], signing::FORMAT);
    let vectors = doc["vectors"].as_array().unwrap();
    assert!(!vectors.is_empty());

    for v in vectors {
        let s = |k: &str| v[k].as_str().unwrap();
        let name = s("name");
        let key = SigningKey::from_bytes(&seed(s("seed_hex")));
        let body = s("body").as_bytes();
        let ts = v["timestamp"].as_u64().unwrap();

        assert_eq!(signing::public_key(&key), s("public_key"), "{name}: public key");
        assert_eq!(signing::sha256_hex(body), s("body_sha256"), "{name}: body hash");
        assert_eq!(
            signing::message(s("method"), s("path"), ts, s("nonce"), body),
            s("message"),
            "{name}: message"
        );
        assert_eq!(
            signing::signature(&key, s("method"), s("path"), ts, s("nonce"), body),
            s("signature"),
            "{name}: signature"
        );
    }
}
