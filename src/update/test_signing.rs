//! A throwaway minisign signer for tests. It writes the same files `minisign -S`
//! does: a prehashed (`ED`) signature over BLAKE2b-512 of the message, or on
//! request a legacy (`Ed`) one over the raw message, plus the global signature
//! over the signature and trusted comment. The seed is the test's secret key;
//! it never leaves test code.
//!
//! Used by the unit tests in `src/update/verify.rs`.

use base64::Engine as _;
use blake2::Digest as _;
use ring::signature::KeyPair as _;

pub struct TestSigner {
    pair: ring::signature::Ed25519KeyPair,
    key_id: [u8; 8],
}

impl TestSigner {
    pub fn new(seed: u8) -> Self {
        let pair = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[seed; 32])
            .expect("test ed25519 seed");
        Self {
            pair,
            key_id: [seed, 0x68, 0x65, 0x72, 0x64, 0x72, 0x75, 0x70],
        }
    }

    /// The `RW…` key line of the matching `minisign.pub`.
    pub fn public_key(&self) -> String {
        let mut bin = Vec::with_capacity(42);
        bin.extend_from_slice(b"Ed");
        bin.extend_from_slice(&self.key_id);
        bin.extend_from_slice(self.pair.public_key().as_ref());
        base64::engine::general_purpose::STANDARD.encode(bin)
    }

    pub fn sign(&self, message: &[u8], trusted_comment: &str) -> String {
        let digest = blake2::Blake2b512::digest(message);
        self.encode(b"ED", &digest, trusted_comment)
    }

    pub fn sign_legacy(&self, message: &[u8], trusted_comment: &str) -> String {
        self.encode(b"Ed", message, trusted_comment)
    }

    fn encode(&self, algorithm: &[u8; 2], signed: &[u8], trusted_comment: &str) -> String {
        let signature = self.pair.sign(signed);
        let mut line = Vec::with_capacity(74);
        line.extend_from_slice(algorithm);
        line.extend_from_slice(&self.key_id);
        line.extend_from_slice(signature.as_ref());
        let mut global = signature.as_ref().to_vec();
        global.extend_from_slice(trusted_comment.as_bytes());
        let global = self.pair.sign(&global);
        let engine = base64::engine::general_purpose::STANDARD;
        format!(
            "untrusted comment: signature from herdr test key\n{}\ntrusted comment: {trusted_comment}\n{}\n",
            engine.encode(line),
            engine.encode(global.as_ref()),
        )
    }
}
