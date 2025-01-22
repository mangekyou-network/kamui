use crate::error::MangekyouError;
use crate::traits::AllowedRng;

use solana_zk_token_sdk::curve25519::ristretto::PodRistrettoPoint;
use solana_zk_token_sdk::curve25519::scalar::PodScalar;

use curve25519_dalek_ng::scalar::Scalar;

/// Represents a public key of which is use to verify outputs for a verifiable random function (VRF).
pub trait VRFPublicKey {
    type PrivateKey: VRFPrivateKey<PublicKey = Self>;
}

/// Represents a private key used to compute outputs for a verifiable random function (VRF).
pub trait VRFPrivateKey {
    type PublicKey: VRFPublicKey<PrivateKey = Self>;
}

/// A keypair for a verifiable random function (VRF).
pub trait VRFKeyPair<const OUTPUT_SIZE: usize> {
    type Proof: VRFProof<OUTPUT_SIZE, PublicKey = Self::PublicKey>;
    type PrivateKey: VRFPrivateKey<PublicKey = Self::PublicKey>;
    type PublicKey: VRFPublicKey<PrivateKey = Self::PrivateKey>;

    /// Generate a new keypair using the given RNG.
    fn generate<R: AllowedRng>(rng: &mut R) -> Self;

    /// Generate a proof for the given input.
    fn prove(&self, input: &[u8]) -> Self::Proof;

    /// Compute both hash and proof for the given input.
    fn output(&self, input: &[u8]) -> ([u8; OUTPUT_SIZE], Self::Proof) {
        let proof = self.prove(input);
        let output = proof.to_hash();
        (output, proof)
    }
}

/// A proof that the output of a VRF was computed correctly.
pub trait VRFProof<const OUTPUT_SIZE: usize> {
    type PublicKey: VRFPublicKey;

    /// Verify the correctness of this proof.
    fn verify(&self, input: &[u8], public_key: &Self::PublicKey) -> Result<(), MangekyouError>;

    /// Verify the correctness of this proof and VRF output.
    fn verify_output(
        &self,
        input: &[u8],
        public_key: &Self::PublicKey,
        output: &[u8; OUTPUT_SIZE],
    ) -> Result<(), MangekyouError> {
        self.verify(input, public_key)?;
        if &self.to_hash() != output {
            return Err(MangekyouError::GeneralOpaqueError);
        }
        Ok(())
    }

    /// Compute the output of the VRF with this proof.
    fn to_hash(&self) -> [u8; OUTPUT_SIZE];

    fn to_bytes(&self) -> Vec<u8>;
}

/// An implementation of an Elliptic Curve VRF (ECVRF) using the Ristretto255 group.
/// The implementation follows the specifications in draft-irtf-cfrg-vrf-15
/// (https://datatracker.ietf.org/doc/draft-irtf-cfrg-vrf/).
pub mod ecvrf {
    use super::*;
    use curve25519_dalek::scalar::Scalar;
    use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use crate::hash::{HashFunction, Sha512};
    use solana_zk_token_sdk::curve25519::{
        ristretto::*,
        scalar::*,
    };
    use borsh::{BorshDeserialize, BorshSerialize};

    #[derive(Clone, Debug)]
    pub struct WrappedPodScalar(pub(crate) PodScalar);

    impl BorshSerialize for WrappedPodScalar {
        fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
            writer.write_all(&self.0.0)
        }
    }

    impl BorshDeserialize for WrappedPodScalar {
        fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
            let mut bytes = [0u8; 32];
            reader.read_exact(&mut bytes)?;
            Ok(Self(PodScalar(bytes)))
        }
    }

    #[derive(Clone, Debug)]
    pub struct WrappedPodRistrettoPoint(pub(crate) PodRistrettoPoint);

    impl BorshSerialize for WrappedPodRistrettoPoint {
        fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
            writer.write_all(&self.0.0)
        }
    }

    impl BorshDeserialize for WrappedPodRistrettoPoint {
        fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
            let mut bytes = [0u8; 32];
            reader.read_exact(&mut bytes)?;
            Ok(Self(PodRistrettoPoint(bytes)))
        }
    }

    /// draft-irtf-cfrg-vrf-15 specifies suites for suite-strings 0x00-0x04 and notes that future
    /// designs should specify a different suite_string constant, so we use "sol_vrf" here.
    const SUITE_STRING: &[u8; 7] = b"sol_vrf";

    /// Length of challenges. Must not exceed the length of field elements which is 32 in this case.
    /// We set C_LEN = 16 which is the same as the existing ECVRF suites in draft-irtf-cfrg-vrf-15.
    const C_LEN: usize = 16;

    /// Default hash function
    type H = Sha512;

    /// Domain separation tag used in ecvrf_encode_to_curve
    const DST: &[u8; 49] = b"ECVRF_ristretto255_XMD:SHA-512_R255MAP_RO_sol_vrf";
    
    /// Domain separation tags for different operations
    const CHALLENGE_GENERATION_DST: &[u8] = b"sol_vrf_challenge_generation";
    const NONCE_GENERATION_DST: &[u8] = b"sol_vrf_nonce_generation";
    const HASH_POINTS_DST: &[u8] = b"sol_vrf_hash_points";

    pub struct ECVRFPublicKey(WrappedPodRistrettoPoint);

    impl VRFPublicKey for ECVRFPublicKey {
        type PrivateKey = ECVRFPrivateKey;
    }

    impl ECVRFPublicKey {
        fn ecvrf_encode_to_curve_solana(&self, alpha_string: &[u8]) -> PodRistrettoPoint {
            // This follows section 5.4.1.2 of draft-irtf-cfrg-vrf-15 for the ristretto255 group using
            // SHA-512. The hash-to-curve for ristretto255 follows appendix B of draft-irtf-cfrg-hash-to-curve-16.
            let mut hasher = H::default();
            hasher.update(DST);
            hasher.update(&[0x00]);
            hasher.update(&self.0.0.0);  // public key bytes
            hasher.update(alpha_string);
            let h1 = hasher.finalize();

            let mut uniform_bytes = [0u8; 64];
            uniform_bytes.copy_from_slice(&h1.digest[..64]);

            let point = RistrettoPoint::from_uniform_bytes(&uniform_bytes);
            PodRistrettoPoint::from(&point)
        }

        fn valid(&self) -> bool {
            let point_bytes = self.0.0.0;
            if point_bytes == [0u8; 32] {
                return false;
            }
            
            CompressedRistretto::from_slice(&point_bytes)
                .decompress()
                .is_some()
        }

        pub fn from_bytes(bytes: &[u8]) -> Result<Self, std::io::Error> {
            if bytes.len() != 32 {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid byte length for ECVRFPublicKey"));
            }
            let mut array = [0u8; 32];
            array.copy_from_slice(bytes);
            Ok(Self(WrappedPodRistrettoPoint(PodRistrettoPoint(array))))
        }
    } 

    impl AsRef<[u8]> for ECVRFPublicKey {
        fn as_ref(&self) -> &[u8] {
            &self.0.0.0
        }
    }

    #[derive(Clone, Debug)]
    pub struct ECVRFPrivateKey(WrappedPodScalar);

    impl VRFPrivateKey for ECVRFPrivateKey {
        type PublicKey = ECVRFPublicKey;
    }

    impl ECVRFPrivateKey {
        fn ecvrf_nonce_generation(&self, h_string: &[u8]) -> PodScalar {
            let mut hasher = Sha512::new();
            hasher.update(NONCE_GENERATION_DST);
            
            // Hash the private key first
            let hashed_sk = {
                let mut h = Sha512::new();
                h.update(&self.0.0.0);
                h.finalize()
            };
            
            // Use the second half of the hashed private key
            let mut truncated_hashed_sk = [0u8; 32];
            truncated_hashed_sk.copy_from_slice(&hashed_sk.digest[32..64]);
            
            // Combine with h_string
            hasher.update(&truncated_hashed_sk);
            hasher.update(h_string);
            
            let k_string = hasher.finalize();
            let mut k_bytes = [0u8; 64];
            k_bytes.copy_from_slice(k_string.digest.as_ref());
            
            // Convert to scalar using wide reduction
            PodScalar::from(&Scalar::from_bytes_mod_order_wide(&k_bytes))
        }

        pub fn from_bytes(bytes: &[u8]) -> Result<Self, std::io::Error> {
            if bytes.len() != 32 {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid byte length for ECVRFPrivateKey"));
            }
            let mut array = [0u8; 32];
            array.copy_from_slice(bytes);
            Ok(Self(WrappedPodScalar(PodScalar(array))))
        }
    }

    impl AsRef<[u8]> for ECVRFPrivateKey {
        fn as_ref(&self) -> &[u8] {
            &self.0.0.0
        }
    }

    pub struct ECVRFKeyPair {
        pub pk: ECVRFPublicKey,
        pub sk: ECVRFPrivateKey,
    }

    /// Generate challenge from five points. See section 5.4.3. of draft-irtf-cfrg-vrf-15.
    fn ecvrf_challenge_generation(points: [&PodRistrettoPoint; 5]) -> Challenge {
        let mut hasher = H::default();
        hasher.update(SUITE_STRING);
        hasher.update([0x02]); // challenge_generation_domain_separator_front
        for p in points.iter() {
            hasher.update(&p.0);  // Use compressed point representation
        }
        hasher.update([0x00]); // challenge_generation_domain_separator_back
        let digest = hasher.finalize();

        let mut challenge_bytes = [0u8; C_LEN];
        challenge_bytes.copy_from_slice(&digest.digest[..C_LEN]);
        Challenge(challenge_bytes)
    }

    /// Type representing a scalar of [C_LEN] bytes. Not targetted to Solana at this time.
    #[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq)]
    pub struct Challenge([u8; C_LEN]);

    impl Challenge {
        fn try_from_slice(bytes: &[u8]) -> Result<Self, std::io::Error> {
            if bytes.len() < C_LEN {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid byte length for Challenge"));
            }
            let mut array = [0u8; C_LEN];
            array.copy_from_slice(&bytes[..C_LEN]);
            Ok(Self(array))
        }
    }

    impl ECVRFKeyPair {
        pub fn from_bytes(bytes: &[u8]) -> Result<Self, std::io::Error> {
            if bytes.len() != 32 * 2 { // Assuming Challenge is also a 32-byte array
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid byte length for KeyPair"));
            }
            let pk_bytes = &bytes[0..32];
            let sk_bytes = &bytes[32..64];
    
            let mut pk_array = [0u8; 32];
            let mut sk_array = [0u8; 32];
    
            pk_array.copy_from_slice(pk_bytes);
            sk_array.copy_from_slice(sk_bytes);
    
            Ok(Self {
                pk: ECVRFPublicKey(WrappedPodRistrettoPoint(PodRistrettoPoint(pk_array))),
                sk: ECVRFPrivateKey(WrappedPodScalar(PodScalar(sk_array)))
            })
        }
    }

    impl VRFKeyPair<64> for ECVRFKeyPair {
        type Proof = ECVRFProof;
        type PrivateKey = ECVRFPrivateKey;
        type PublicKey = ECVRFPublicKey;

        fn generate<R: AllowedRng>(rng: &mut R) -> Self {
            let mut scalar_bytes = [0u8; 64];
            rng.fill_bytes(&mut scalar_bytes);
            
            let s = PodScalar::from(&Scalar::from_bytes_mod_order_wide(&scalar_bytes));
            ECVRFKeyPair::from(ECVRFPrivateKey(WrappedPodScalar(s)))
        }
        
        fn prove(&self, alpha_string: &[u8]) -> ECVRFProof {
            let h_point = self.pk.ecvrf_encode_to_curve_solana(alpha_string);

            let gamma = multiply_ristretto(&PodScalar::from(&self.sk.0), &h_point).unwrap();
    
            let k = self.sk.ecvrf_nonce_generation(alpha_string);
    
            let c = ecvrf_challenge_generation([
                &PodRistrettoPoint::from(&self.pk.0),  // Y (public key)
                &h_point,                               // H
                &gamma,                                 // Gamma
                &multiply_ristretto(&k, &PodRistrettoPoint::from(&RISTRETTO_BASEPOINT_POINT)).unwrap(), // U = k*B
                &multiply_ristretto(&k, &h_point).unwrap()  // V = k*H
            ]);
    
            let k_scalar = Scalar::try_from(k).unwrap();
            let sk_scalar = Scalar::try_from(&self.sk.0).unwrap();
            
            // Convert challenge to scalar
            let mut scalar_bytes = [0u8; 32];
            scalar_bytes[..C_LEN].copy_from_slice(&c.0);
            let c_scalar = Scalar::from_bytes_mod_order(scalar_bytes);
            
            let s = k_scalar + c_scalar * sk_scalar;
    
            ECVRFProof { 
                gamma, 
                c, 
                s: PodScalar::from(&s)
            }
        }
    }

    impl From<ECVRFPrivateKey> for ECVRFKeyPair {
        fn from(sk: ECVRFPrivateKey) -> Self {
            let p = PodRistrettoPoint::from(&(RISTRETTO_BASEPOINT_POINT * Scalar::try_from(sk.0.0).unwrap()));
            ECVRFKeyPair {
                pk: ECVRFPublicKey(WrappedPodRistrettoPoint(p)),
                sk,
            }
        }
    }

    pub struct ECVRFProof {
        gamma: PodRistrettoPoint,
        c: Challenge,
        s: PodScalar,
    }

    impl ECVRFProof {
        pub fn from_bytes(bytes: &[u8]) -> Result<Self, std::io::Error> {
            if bytes.len() <= 32 * 2 { 
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid byte length for ECVRFProof"));
            }
            let gamma_bytes = &bytes[0..32];
            let c_bytes = &bytes[32..32+C_LEN];  // Challenge is C_LEN bytes
            let s_bytes = &bytes[32+C_LEN..32+C_LEN+32];  // Last 32 bytes are the scalar
    
            let mut gamma_array = [0u8; 32];
            let mut s_array = [0u8; 32];
    
            gamma_array.copy_from_slice(gamma_bytes);
            s_array.copy_from_slice(s_bytes);
    
            Ok(Self {
                gamma: PodRistrettoPoint(gamma_array),
                c: Challenge::try_from_slice(c_bytes).unwrap(),
                s: PodScalar(s_array),
            })
        }
    }

    impl VRFProof<64> for ECVRFProof {
        type PublicKey = ECVRFPublicKey;

        fn verify(
            &self,
            alpha_string: &[u8],
            public_key: &Self::PublicKey,
        ) -> Result<(), MangekyouError> {
            // Ensure the public key is valid in constant time
            if !public_key.valid() {
                return Err(MangekyouError::InvalidInput);
            }

            // Encode the input alpha_string to a curve point using the public key method
            let h_point = public_key.ecvrf_encode_to_curve_solana(alpha_string);

            // Convert challenge to scalar and negate it
            let mut c_scalar = [0u8; 32];
            c_scalar[..C_LEN].copy_from_slice(&self.c.0);
            let neg_challenge = negate_scalar(&PodScalar(c_scalar));

            // Create basepoint
            let basepoint = PodRistrettoPoint::from(&RISTRETTO_BASEPOINT_POINT);

            // Compute both points in a single multiscalar multiplication for efficiency
            let u_point = multiscalar_multiply_ristretto(
                &[self.s, neg_challenge],
                &[basepoint, public_key.0.0.clone()],
            ).ok_or(MangekyouError::InvalidInput)?;

            let v_point = multiscalar_multiply_ristretto(
                &[self.s, neg_challenge],
                &[h_point, self.gamma],
            ).ok_or(MangekyouError::InvalidInput)?;

            // Recompute the challenge in constant time
            let c_prime = ecvrf_challenge_generation([
                &public_key.0.0,      // Y (public key)
                &h_point,             // H
                &self.gamma,          // Gamma
                &u_point,             // U = s*B - c*Y
                &v_point,             // V = s*H - c*Gamma
            ]);

            // Constant time comparison
            if c_prime != self.c {
                return Err(MangekyouError::GeneralOpaqueError);
            }

            Ok(())
        }

        fn to_hash(&self) -> [u8; 64] {
            // Follows section 5.2 of draft-irtf-cfrg-vrf-15.
            let mut hash = H::default();
            hash.update(SUITE_STRING);
            hash.update([0x03]); // proof_to_hash_domain_separator_front
            hash.update(self.gamma.0);
            hash.update([0x00]); // proof_to_hash_domain_separator_back
            hash.finalize().digest
        }

        fn to_bytes(&self) -> Vec<u8> {
            // Convert each field to a byte array and concatenate them
            let gamma_bytes = self.gamma.0;
            
            let mut c_buffer: Vec<u8> = Vec::new();
            self.c.serialize(&mut c_buffer);
            
            let s_bytes = self.s.0;
    
            let concatenated = [gamma_bytes.as_ref(), c_buffer.as_ref(), s_bytes.as_ref()].concat();
            concatenated
        }
    }

    // Add these implementations after the wrapper type definitions
    impl From<&WrappedPodScalar> for PodScalar {
        fn from(w: &WrappedPodScalar) -> Self {
            w.0.clone()
        }
    }

    impl From<&WrappedPodRistrettoPoint> for PodRistrettoPoint {
        fn from(w: &WrappedPodRistrettoPoint) -> Self {
            w.0.clone()
        }
    }

    impl From<PodScalar> for WrappedPodScalar {
        fn from(p: PodScalar) -> Self {
            Self(p)
        }
    }

    impl From<PodRistrettoPoint> for WrappedPodRistrettoPoint {
        fn from(p: PodRistrettoPoint) -> Self {
            Self(p)
        }
    }

    // Add conversion to Scalar
    impl TryFrom<&WrappedPodScalar> for Scalar {
        type Error = MangekyouError;

        fn try_from(value: &WrappedPodScalar) -> Result<Self, Self::Error> {
            Scalar::try_from(value.0.clone()).map_err(|_| MangekyouError::InvalidInput)
        }
    }

    /// Helper function to convert bytes to PodScalar
    fn bytes_to_scalar(bytes: &[u8]) -> PodScalar {
        let mut scalar = [0u8; 32];
        scalar[..bytes.len()].copy_from_slice(bytes);
        PodScalar(scalar)
    }

    /// Helper function to negate a scalar
    fn negate_scalar(scalar: &PodScalar) -> PodScalar {
        let mut neg_bytes = [0u8; 32];
        let mut carry = 0i16;
        
        // L - x mod L, where L is the order of the curve
        let order = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
            0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
        ];
        
        // Compute L - x
        for i in 0..32 {
            let diff = order[i] as i16 - scalar.0[i] as i16 - carry;
            if diff < 0 {
                carry = 1;
                neg_bytes[i] = (diff + 256) as u8;
            } else {
                carry = 0;
                neg_bytes[i] = diff as u8;
            }
        }
        
        PodScalar(neg_bytes)
    }
}

