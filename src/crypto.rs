//! Signing keys, signatures and `did:key`.
//!
//! Both curves verify, because a key minted elsewhere may be either, but only
//! secp256k1 is worth generating: it is what the reference generates and what
//! the PLC directory expects.

use std::{fmt, str::FromStr};

use k256::ecdsa::signature::{Signer, Verifier};
use k256::elliptic_curve::Generate;

/// Multicodec, varint-encoded, in front of the compressed point.
const SECP256K1_PREFIX: [u8; 2] = [0xe7, 0x01];
const P256_PREFIX: [u8; 2] = [0x80, 0x24];

/// A compressed SEC1 point: the sign byte and one coordinate.
const POINT_LEN: usize = 33;

/// Bytes as lowercase hex, which is how a key in the environment and a salt in
/// the account database are both written.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut written, byte| {
        let _ = write!(written, "{byte:02x}");
        written
    })
}

/// The curves atproto allows.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Algorithm {
    /// NIST P-256, `ES256`.
    P256,
    /// secp256k1, `ES256K`.
    Secp256k1,
}

/// A key that can sign.
#[derive(Clone, Debug)]
pub enum Keypair {
    /// A P-256 key.
    P256(p256::ecdsa::SigningKey),
    /// A secp256k1 key.
    Secp256k1(k256::ecdsa::SigningKey),
}

/// A key that can only verify, and the thing a `did:key` names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicKey {
    /// A P-256 key.
    P256(p256::ecdsa::VerifyingKey),
    /// A secp256k1 key.
    Secp256k1(k256::ecdsa::VerifyingKey),
}

/// Why a key or a signature was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum Error {
    /// The string was not `did:key:z` followed by base58btc.
    #[error("not a did:key")]
    NotDidKey,
    /// Some other multicodec, or an uncompressed point.
    #[error("not a key on an allowed curve")]
    UnsupportedKey,
    /// The bytes are the right shape but not a point or a scalar.
    #[error("malformed key")]
    MalformedKey,
    /// Length is the whole check, which is also what rejects DER: an encoded
    /// pair of integers is never exactly 64 bytes.
    #[error("signature is not 64 bytes")]
    MalformedSignature,
    /// Both halves of the curve give a valid signature, so only one of them is
    /// allowed to count.
    #[error("signature does not use the low half of the curve")]
    HighS,
    /// The signature is well formed and wrong.
    #[error("signature does not verify")]
    BadSignature,
}

impl Keypair {
    /// Makes a new key from the system's randomness.
    #[must_use]
    pub fn generate(algorithm: Algorithm) -> Self {
        match algorithm {
            Algorithm::P256 => Self::P256(p256::ecdsa::SigningKey::generate()),
            Algorithm::Secp256k1 => Self::Secp256k1(k256::ecdsa::SigningKey::generate()),
        }
    }

    /// Reads the 32-byte scalar written by [`Keypair::to_bytes`].
    ///
    /// # Errors
    ///
    /// If the bytes are not a scalar on that curve.
    pub fn from_bytes(algorithm: Algorithm, bytes: &[u8]) -> Result<Self, Error> {
        match algorithm {
            Algorithm::P256 => p256::ecdsa::SigningKey::from_slice(bytes).map(Self::P256),
            Algorithm::Secp256k1 => k256::ecdsa::SigningKey::from_slice(bytes).map(Self::Secp256k1),
        }
        .map_err(|_| Error::MalformedKey)
    }

    /// The private scalar, which is the whole secret.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::P256(key) => key.to_bytes().to_vec(),
            Self::Secp256k1(key) => key.to_bytes().to_vec(),
        }
    }

    /// The curve this key is on.
    #[must_use]
    pub fn algorithm(&self) -> Algorithm {
        match self {
            Self::P256(_) => Algorithm::P256,
            Self::Secp256k1(_) => Algorithm::Secp256k1,
        }
    }

    /// The half that can be published.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        match self {
            Self::P256(key) => PublicKey::P256(*key.verifying_key()),
            Self::Secp256k1(key) => PublicKey::Secp256k1(*key.verifying_key()),
        }
    }

    /// Signs the sha-256 of `message`, normalizing to the low half.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let bytes = match self {
            Self::P256(key) => {
                let signature: p256::ecdsa::Signature = key.sign(message);
                signature.normalize_s().to_bytes()
            }
            Self::Secp256k1(key) => {
                let signature: k256::ecdsa::Signature = key.sign(message);
                signature.normalize_s().to_bytes()
            }
        };
        bytes.into()
    }
}

impl PublicKey {
    /// Checks a compact signature over `message`.
    ///
    /// # Errors
    ///
    /// If the signature is malformed, malleable, or simply wrong.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Error> {
        match self {
            Self::P256(key) => {
                let signature = p256::ecdsa::Signature::from_slice(signature)
                    .map_err(|_| Error::MalformedSignature)?;
                if signature.normalize_s() != signature {
                    return Err(Error::HighS);
                }
                key.verify(message, &signature)
            }
            Self::Secp256k1(key) => {
                let signature = k256::ecdsa::Signature::from_slice(signature)
                    .map_err(|_| Error::MalformedSignature)?;
                if signature.normalize_s() != signature {
                    return Err(Error::HighS);
                }
                key.verify(message, &signature)
            }
        }
        .map_err(|_| Error::BadSignature)
    }

    /// The curve this key is on.
    #[must_use]
    pub fn algorithm(&self) -> Algorithm {
        match self {
            Self::P256(_) => Algorithm::P256,
            Self::Secp256k1(_) => Algorithm::Secp256k1,
        }
    }

    /// The multicodec prefix and the compressed point, which is what both the
    /// `did:key` and the PLC operation carry.
    #[must_use]
    pub fn to_multicodec(&self) -> Vec<u8> {
        let (prefix, point) = match self {
            Self::P256(key) => (P256_PREFIX, key.to_sec1_point(true)),
            Self::Secp256k1(key) => (SECP256K1_PREFIX, key.to_sec1_point(true)),
        };
        let mut bytes = Vec::with_capacity(prefix.len() + POINT_LEN);
        bytes.extend_from_slice(&prefix);
        bytes.extend_from_slice(point.as_ref());
        bytes
    }

    /// Reads the encoding [`PublicKey::to_multicodec`] writes.
    ///
    /// # Errors
    ///
    /// If the curve is not one of the two, or the point does not decompress.
    pub fn from_multicodec(bytes: &[u8]) -> Result<Self, Error> {
        let Some((prefix, point)) = bytes.split_at_checked(2) else {
            return Err(Error::UnsupportedKey);
        };
        if point.len() != POINT_LEN {
            return Err(Error::UnsupportedKey);
        }
        if *prefix == P256_PREFIX {
            p256::ecdsa::VerifyingKey::from_sec1_bytes(point).map(Self::P256)
        } else if *prefix == SECP256K1_PREFIX {
            k256::ecdsa::VerifyingKey::from_sec1_bytes(point).map(Self::Secp256k1)
        } else {
            return Err(Error::UnsupportedKey);
        }
        .map_err(|_| Error::MalformedKey)
    }
}

impl fmt::Display for PublicKey {
    /// Writes the `did:key`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let encoded = bs58::encode(self.to_multicodec()).into_string();
        write!(f, "did:key:z{encoded}")
    }
}

impl FromStr for PublicKey {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let encoded = input.strip_prefix("did:key:z").ok_or(Error::NotDidKey)?;
        let bytes = bs58::decode(encoded)
            .into_vec()
            .map_err(|_| Error::NotDidKey)?;
        Self::from_multicodec(&bytes)
    }
}
