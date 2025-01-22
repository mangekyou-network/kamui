// Copyright (c) 2022, Mangekyou Network, Inc.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    encoding::{Base64, Encoding},
    error::MangekyouError,
    hash::HashFunction,
};
#[cfg(any(test, feature = "experimental"))]
use eyre::eyre;
use rand::rngs::{StdRng, ThreadRng};
use rand::{CryptoRng, RngCore};
use serde::{de::DeserializeOwned, Serialize};
use std::{
    borrow::Borrow,
    fmt::{Debug, Display},
    str::FromStr,
};

/// Trait impl'd by concrete types that represent digital cryptographic material
/// (keys).
///
/// Key types *must* (as mandated by the `AsRef<[u8]>` bound) be a thin
/// wrapper around the "bag-of-bytes" serialized form of a key which can
/// be directly parsed from or written to the "wire".
///
/// The [`ToFromBytes`] trait aims to provide similar simplicity by minimizing
/// the number of steps involved to obtain a serializable key and
/// ideally ensuring there is one signature type for any given signature system
/// shared by all "provider" crates.
///
/// For signature systems which require a more advanced internal representation
/// (e.g. involving decoded scalars or decompressed elliptic curve points) it's
/// recommended that "provider" libraries maintain their own internal signature
/// type and use `From` bounds to provide automatic conversions.
///
pub trait ToFromBytes: AsRef<[u8]> + Debug + Sized {
    /// Parse an object from its byte representation
    fn from_bytes(bytes: &[u8]) -> Result<Self, MangekyouError>;

    /// Borrow a byte slice representing the serialized form of this object
    fn as_bytes(&self) -> &[u8] {
        self.as_ref()
    }
}

/// Cryptographic material with an immediate conversion to/from Base64 strings.
///
/// This is an [extension trait](https://rust-lang.github.io/rfcs/0445-extension-trait-conventions.html) of `ToFromBytes` above.
///
pub trait EncodeDecodeBase64: Sized {
    fn encode_base64(&self) -> String;
    fn decode_base64(value: &str) -> Result<Self, eyre::Report>;
}

impl<T: ToFromBytes> EncodeDecodeBase64 for T {
    fn encode_base64(&self) -> String {
        Base64::encode(self.as_bytes())
    }

    fn decode_base64(value: &str) -> Result<Self, eyre::Report> {
        let bytes = Base64::decode(value)?;
        <T as ToFromBytes>::from_bytes(&bytes).map_err(|e| e.into())
    }
}

/// Trait impl'd by public keys in asymmetric cryptography.
///
/// The trait bounds are implemented so as to be symmetric and equivalent
/// to the ones on its associated types for private and signature material.
///
pub trait VerifyingKey:
    Serialize
    + DeserializeOwned
    + std::hash::Hash
    + Display
    + Eq  // required to make some cached bytes representations explicit.
    + Ord // required to put keys in BTreeMap.
    + ToFromBytes
    + for<'a> From<&'a Self::PrivKey> // conversion PrivateKey -> PublicKey.
    + Send
    + Sync
    + 'static
    + Clone
{
    type PrivKey: SigningKey<PubKey=Self>;
    type Sig: Authenticator<PubKey=Self>;
    const LENGTH: usize;

    /// Use Self to verify that the provided signature for a given message bytestring is authentic.
    /// Returns Error if it is inauthentic, or otherwise returns ().
    fn verify(&self, msg: &[u8], signature: &Self::Sig) -> Result<(), MangekyouError>;

    // Expected to be overridden by implementations
    /// Batch verification over the same message. Implementations of this method can be fast,
    /// assuming rogue key checks have already been performed.
    /// TODO: take as input a flag to denote if rogue key protection already took place.
    ///
    /// # Example
    /// ```rust
    /// use mangekyou::ed25519::*;
    /// # use mangekyou::{traits::{KeyPair, Signer, VerifyingKey}};
    /// use rand::thread_rng;
    /// let message: &[u8] = b"Hello, world!";
    /// let kp1 = Ed25519KeyPair::generate(&mut thread_rng());
    /// let signature1 = kp1.sign(message);
    /// let kp2 = Ed25519KeyPair::generate(&mut thread_rng());
    /// let signature2 = kp2.sign(message);
    /// let public_keys = [kp1.public().clone(), kp2.public().clone()];
    /// let signatures = [signature1.clone(), signature2.clone()];
    /// assert!(Ed25519PublicKey::verify_batch_empty_fail(message, &public_keys, &signatures).is_ok());
    /// ```
    #[cfg(any(test, feature = "experimental"))]
    fn verify_batch_empty_fail(msg: &[u8], pks: &[Self], sigs: &[Self::Sig]) -> Result<(), eyre::Report> {
        if sigs.is_empty() {
            return Err(eyre!("Critical Error! This behaviour can signal something dangerous, and that someone may be trying to bypass signature verification through providing empty batches."));
        }
        if pks.len() != sigs.len() {
            return Err(eyre!("Mismatch between number of signatures and public keys provided"));
        }
        pks.iter()
            .zip(sigs)
            .try_for_each(|(pk, sig)| pk.verify(msg, sig))
            .map_err(|_| eyre!("Signature verification failed"))
    }

    /// Batch verification over different messages. Implementations of this method can be fast,
    /// assuming rogue key checks have already been performed.
    /// TODO: take as input a flag to denote if rogue key protection already took place.
    ///
    /// # Example
    /// ```rust
    /// use mangekyou::ed25519::*;
    /// # use mangekyou::traits::{KeyPair, Signer, VerifyingKey};
    /// use rand::thread_rng;
    /// let message1: &[u8] = b"Hello, world!";
    /// let kp1 = Ed25519KeyPair::generate(&mut thread_rng());
    /// let signature1 = kp1.sign(message1);
    /// let message2: &[u8] = b"Hello, world!!!";
    /// let kp2 = Ed25519KeyPair::generate(&mut thread_rng());
    /// let signature2 = kp2.sign(message2);
    /// let messages = [message1, message2];
    /// let public_keys = [kp1.public().clone(), kp2.public().clone()];
    /// let signatures = [signature1.clone(), signature2.clone()];
    /// assert!(Ed25519PublicKey::verify_batch_empty_fail_different_msg(&messages, &public_keys, &signatures).is_ok());
    /// ```
    #[cfg(any(test, feature = "experimental"))]
    fn verify_batch_empty_fail_different_msg<'a, M>(msgs: &[M], pks: &[Self], sigs: &[Self::Sig]) -> Result<(), eyre::Report> where M: Borrow<[u8]> + 'a {
        if sigs.is_empty() {
            return Err(eyre!("Critical Error! This behaviour can signal something dangerous, and that someone may be trying to bypass signature verification through providing empty batches."));
        }
        if pks.len() != sigs.len() || pks.len() != msgs.len() {
            return Err(eyre!("Mismatch between number of messages, signatures and public keys provided"));
        }
        pks.iter()
            .zip(sigs)
            .zip(msgs)
            .try_for_each(|((pk, sig), msg)| pk.verify(msg.borrow(), sig))
            .map_err(|_| eyre!("Signature verification failed"))
    }
}

/// Trait impl'd by private (secret) keys in asymmetric cryptography.
///
/// The trait bounds are implemented so as to be symmetric and equivalent
/// to the ones on its associated types for public key and signature material.
///
pub trait SigningKey: ToFromBytes + Serialize + DeserializeOwned + Send + Sync + 'static {
    type PubKey: VerifyingKey<PrivKey = Self>;
    type Sig: Authenticator<PrivKey = Self>;
    const LENGTH: usize;
}

/// Trait impl'd by signatures in asymmetric cryptography.
///
/// The trait bounds are implemented so as to be symmetric and equivalent
/// to the ones on its associated types for private key and public key material.
///
pub trait Authenticator:
    ToFromBytes + Display + Serialize + DeserializeOwned + Send + Sync + 'static + Clone
{
    type PubKey: VerifyingKey<Sig = Self>;
    type PrivKey: SigningKey<Sig = Self>;
    const LENGTH: usize;
}

/// Trait impl'd by a key/keypair that can create signatures.
///
pub trait Signer<Sig> {
    /// Create a new signature over a message.
    fn sign(&self, msg: &[u8]) -> Sig;
}

/// Trait impl'd by a public / private key pair in asymmetric cryptography.
///
pub trait KeyPair:
    Sized + From<Self::PrivKey> + Signer<Self::Sig> + EncodeDecodeBase64 + FromStr
{
    type PubKey: VerifyingKey<PrivKey = Self::PrivKey, Sig = Self::Sig>;
    type PrivKey: SigningKey<PubKey = Self::PubKey, Sig = Self::Sig>;
    type Sig: Authenticator<PubKey = Self::PubKey, PrivKey = Self::PrivKey>;

    /// Get the public key.
    fn public(&'_ self) -> &'_ Self::PubKey;
    /// Get the private key.
    fn private(self) -> Self::PrivKey;

    #[cfg(feature = "copy_key")]
    fn copy(&self) -> Self;

    /// Generate a new keypair using the given RNG.
    fn generate<R: AllowedRng>(rng: &mut R) -> Self;
}

/// Trait impl'd by public / private keypairs that can generate recoverable signatures
pub trait RecoverableSigner {
    type PubKey;
    type Sig: RecoverableSignature<Signer = Self, PubKey = Self::PubKey>;

    /// Sign as a recoverable signature.
    fn sign_recoverable(&self, msg: &[u8]) -> Self::Sig {
        self.sign_recoverable_with_hash::<<<Self as RecoverableSigner>::Sig as RecoverableSignature>::DefaultHash>(msg)
    }

    /// Sign as a recoverable signature using the given hash function.
    ///
    /// Note: This is currently only used for Secp256r1 and Secp256k1 where the hash function must have 32 byte output.
    fn sign_recoverable_with_hash<H: HashFunction<32>>(&self, msg: &[u8]) -> Self::Sig;
}

pub trait VerifyRecoverable: Eq + Sized {
    type Sig: RecoverableSignature<PubKey = Self>;

    /// Verify a recoverable signature by recovering the public key and compare it to self.
    fn verify_recoverable(&self, msg: &[u8], signature: &Self::Sig) -> Result<(), MangekyouError> {
        self.verify_recoverable_with_hash::<<<Self as VerifyRecoverable>::Sig as RecoverableSignature>::DefaultHash>(msg, signature)
    }

    /// Verify a recoverable signature by recovering the public key and compare it to self.
    /// The recovery is using the given hash function.
    ///
    /// Note: This is currently only used for Secp256r1 and Secp256k1 where the hash function must have 32 byte output.
    fn verify_recoverable_with_hash<H: HashFunction<32>>(
        &self,
        msg: &[u8],
        signature: &Self::Sig,
    ) -> Result<(), MangekyouError> {
        match signature.recover_with_hash::<H>(msg)? == *self {
            true => Ok(()),
            false => Err(MangekyouError::InvalidSignature),
        }
    }
}

pub trait RecoverableSignature: Sized {
    type PubKey;
    type Signer: RecoverableSigner<Sig = Self, PubKey = Self::PubKey>;
    type DefaultHash: HashFunction<32>;

    /// Recover the public key from this signature.
    fn recover(&self, msg: &[u8]) -> Result<Self::PubKey, MangekyouError> {
        self.recover_with_hash::<Self::DefaultHash>(msg)
    }

    /// Recover the public key from this signature. Assuming that the given hash function was used for signing.
    ///
    /// Note: This is currently only used for Secp256r1 and Secp256k1 where the hash function must have 32 byte output.
    fn recover_with_hash<H: HashFunction<32>>(
        &self,
        msg: &[u8],
    ) -> Result<Self::PubKey, MangekyouError>;
}

/// Trait impl'd by cryptographic material that can be generated randomly such as keys and nonces.
///
pub trait Generate {
    /// Generate a new random instance using the given RNG.
    fn generate<R: AllowedRng>(rng: &mut R) -> Self;
}

/// Trait impl'd by a keys/secret seeds for generating a secure instance.
///
pub trait FromUniformBytes<const LENGTH: usize>: ToFromBytes {
    fn generate<R: AllowedRng>(rng: &mut R) -> Self {
        let mut bytes = [0u8; LENGTH];
        rng.fill_bytes(&mut bytes);
        Self::from_bytes(&bytes).unwrap()
    }
}

/// Trait for objects that support an insecure default value that should **only** be used as a
/// placeholder.
pub trait InsecureDefault {
    fn insecure_default() -> Self;
}

// Whitelist the RNG our APIs accept (see https://rust-random.github.io/book/guide-rngs.html for
// others).
/// Trait impl'd by RNG's accepted by mangekyou.
pub trait AllowedRng: CryptoRng + RngCore {}

// StdRng uses ChaCha12 (see https://github.com/rust-random/rand/issues/932).
// It should be seeded with OsRng (e.g., StdRng::from_rng(OsRng)).
impl AllowedRng for StdRng {}
// thread_rng() uses OsRng for the seed, and ChaCha12 as the PRG function.
impl AllowedRng for ThreadRng {}
