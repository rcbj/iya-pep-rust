// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! The PEP's own key (D1): it signs the RFC 7523 self-assertion and every
//! DPoP proof, so each token is bound to it. EC P-256 (ES256) is preferred;
//! RSA of 2048 bits or more (RS256) is accepted. Nothing else is.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::signature::Signer;
use p256::pkcs8::DecodePrivateKey as _;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use rsa::traits::PublicKeyParts;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::error::PepError;

/// The smallest RSA modulus accepted, in bits.
pub const MIN_RSA_BITS: usize = 2048;

pub fn b64url(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

enum Inner {
    Ec(p256::ecdsa::SigningKey),
    Rsa(Box<rsa::pkcs1v15::SigningKey<Sha256>>),
}

/// A loaded signing key, its public JWK and its RFC 7638 thumbprint.
pub struct SigningKey {
    inner: Inner,
    jwk: Value,
    thumbprint: String,
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the private half.
        f.debug_struct("SigningKey").field("alg", &self.alg()).field("thumbprint", &self.thumbprint).finish()
    }
}

impl SigningKey {
    /// Reads a PEM private key: PKCS #8 (`PRIVATE KEY`), SEC 1
    /// (`EC PRIVATE KEY`) or PKCS #1 (`RSA PRIVATE KEY`).
    pub fn from_pem(pem: &str) -> Result<Self, PepError> {
        if let Ok(key) = p256::ecdsa::SigningKey::from_pkcs8_pem(pem) {
            return Ok(Self::ec(key));
        }
        if let Ok(secret) = p256::SecretKey::from_sec1_pem(pem) {
            return Ok(Self::ec(p256::ecdsa::SigningKey::from(secret)));
        }
        let rsa = <rsa::RsaPrivateKey as rsa::pkcs8::DecodePrivateKey>::from_pkcs8_pem(pem).or_else(|_| rsa::RsaPrivateKey::from_pkcs1_pem(pem));
        if let Ok(key) = rsa {
            let bits = key.size() * 8;
            if bits < MIN_RSA_BITS {
                return Err(PepError::new("config", format!("the assertion key is RSA of {bits} bits; at least {MIN_RSA_BITS} are required")));
            }
            let n = b64url(&key.n().to_bytes_be());
            let e = b64url(&key.e().to_bytes_be());
            let canonical = format!("{{\"e\":\"{e}\",\"kty\":\"RSA\",\"n\":\"{n}\"}}");
            return Ok(Self {
                inner: Inner::Rsa(Box::new(rsa::pkcs1v15::SigningKey::<Sha256>::new(key))),
                jwk: json!({"kty": "RSA", "n": n, "e": e}),
                thumbprint: b64url(&Sha256::digest(canonical.as_bytes())),
            });
        }
        Err(PepError::new("config", "the assertion key is neither an EC P-256 nor an RSA private key in PEM"))
    }

    fn ec(key: p256::ecdsa::SigningKey) -> Self {
        let point = key.verifying_key().to_sec1_point(false);
        let x = b64url(point.x().map(|v| v.as_slice()).unwrap_or_default());
        let y = b64url(point.y().map(|v| v.as_slice()).unwrap_or_default());
        // RFC 7638: the required members only, in lexicographic order.
        let canonical = format!("{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}");
        Self {
            inner: Inner::Ec(key),
            jwk: json!({"kty": "EC", "crv": "P-256", "x": x, "y": y}),
            thumbprint: b64url(&Sha256::digest(canonical.as_bytes())),
        }
    }

    /// `ES256` or `RS256`.
    pub fn alg(&self) -> &'static str {
        match self.inner {
            Inner::Ec(_) => "ES256",
            Inner::Rsa(_) => "RS256",
        }
    }

    /// The public key as a JWK.
    pub fn jwk(&self) -> &Value {
        &self.jwk
    }

    /// The RFC 7638 SHA-256 thumbprint, base64url.
    pub fn thumbprint(&self) -> &str {
        &self.thumbprint
    }

    /// A compact JWS of `claims` under `header` (to which `alg` is added).
    pub fn jws(&self, mut header: Value, claims: &Value) -> String {
        header["alg"] = Value::String(self.alg().to_string());
        let encode = |value: &Value| b64url(&serde_json::to_vec(value).unwrap_or_default());
        let input = format!("{}.{}", encode(&header), encode(claims));
        let signature = match &self.inner {
            // RFC 7518 section 3.4: R and S, each 32 bytes, concatenated.
            Inner::Ec(key) => {
                let sig: p256::ecdsa::Signature = key.sign(input.as_bytes());
                sig.to_bytes().to_vec()
            }
            Inner::Rsa(key) => key.sign_with_rng(&mut rand::thread_rng(), input.as_bytes()).to_vec(),
        };
        format!("{input}.{}", b64url(&signature))
    }
}

/// The RFC 7638 thumbprint of a public JWK (EC, RSA or OKP), for a host
/// library comparing its own keys with the PEP's. `None` for a JWK this
/// can't canonicalise.
pub fn jwk_thumbprint(jwk: &Value) -> Option<String> {
    let s = |name: &str| jwk.get(name).and_then(Value::as_str);
    let canonical = match s("kty")? {
        "EC" => format!("{{\"crv\":\"{}\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}", s("crv")?, s("x")?, s("y")?),
        "RSA" => format!("{{\"e\":\"{}\",\"kty\":\"RSA\",\"n\":\"{}\"}}", s("e")?, s("n")?),
        "OKP" => format!("{{\"crv\":\"{}\",\"kty\":\"OKP\",\"x\":\"{}\"}}", s("crv")?, s("x")?),
        _ => return None,
    };
    Some(b64url(&Sha256::digest(canonical.as_bytes())))
}

/// The RFC 7638 thumbprint of a PEM private key's public half (EC P-256 or
/// RSA ≥ 2048), for a host library comparing a key file of its own (a TLS
/// client key, a signing key) with the PEP's. `None` for a key this crate
/// can't read.
pub fn pem_thumbprint(pem: &str) -> Option<String> {
    SigningKey::from_pem(pem).ok().map(|k| k.thumbprint().to_string())
}

/// 128 random bits as hex, for a `jti`.
pub fn random_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A P-256 key for the tests, PKCS #8.
    pub fn ec_pem() -> String {
        use p256::pkcs8::EncodePrivateKey;
        let key = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
        key.to_pkcs8_pem(Default::default()).unwrap().to_string()
    }

    #[test]
    fn an_ec_key_signs_es256_with_a_64_byte_signature() {
        let key = SigningKey::from_pem(&ec_pem()).unwrap();
        assert_eq!(key.alg(), "ES256");
        let jws = key.jws(json!({"typ": "JWT"}), &json!({"a": 1}));
        let parts: Vec<&str> = jws.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(URL_SAFE_NO_PAD.decode(parts[2]).unwrap().len(), 64);
        let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header["alg"], "ES256");
        assert_eq!(jwk_thumbprint(key.jwk()).as_deref(), Some(key.thumbprint()));
    }

    #[test]
    fn a_pem_thumbprint_is_the_keys() {
        let key = SigningKey::from_pem(&ec_pem()).unwrap();
        assert_eq!(pem_thumbprint(&ec_pem()).as_deref(), Some(key.thumbprint()));
        assert_eq!(pem_thumbprint("garbage"), None);
    }

    #[test]
    fn a_small_rsa_key_and_garbage_are_refused() {
        use rsa::pkcs8::EncodePrivateKey;
        let small = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 1024).unwrap();
        let pem = small.to_pkcs8_pem(Default::default()).unwrap();
        let err = SigningKey::from_pem(&pem).unwrap_err();
        assert!(err.message.contains("1024"), "{err}");
        assert_eq!(SigningKey::from_pem("not a key").unwrap_err().code, "config");
    }

    #[test]
    fn an_rsa_key_signs_rs256_and_has_a_stable_thumbprint() {
        use rsa::pkcs8::EncodePrivateKey;
        let key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let pem = key.to_pkcs8_pem(Default::default()).unwrap();
        let loaded = SigningKey::from_pem(&pem).unwrap();
        assert_eq!(loaded.alg(), "RS256");
        assert_eq!(jwk_thumbprint(loaded.jwk()).as_deref(), Some(loaded.thumbprint()));
    }
}
