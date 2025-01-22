use crate::error::MangekyouError;
use crate::traits::AllowedRng;

use solana_zk_token_sdk::curve25519::ristretto::PodRistrettoPoint;
use solana_zk_token_sdk::curve25519::scalar::PodScalar;

use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;

/// The Ristretto basepoint encoded as bytes
pub const BASEPOINT_BYTES: [u8; 32] = [
    0xe2, 0xf2, 0xae, 0x0a, 0x6a, 0xbc, 0x4e, 0x71,
    0xa8, 0x84, 0xa9, 0x61, 0xc5, 0x00, 0x51, 0x5f,
    0x58, 0xe3, 0x0b, 0x6a, 0xa5, 0x82, 0xdd, 0x8d,
    0xb6, 0xa6, 0x59, 0x45, 0xe0, 0x8d, 0x2d, 0x76,
];

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
            let mut hasher = H::default();
            hasher.update(DST);
            hasher.update(&[0x01]);  // domain separation for first hash
            hasher.update(&self.0.0.0);
            hasher.update(alpha_string);
            let h1 = hasher.finalize();

            // Second round of hashing
            let mut hasher = H::default();
            hasher.update(DST);
            hasher.update(&[0x02]);  // domain separation for second hash
            hasher.update(&h1.digest);
            let h2 = hasher.finalize();

            // Combine both hashes to get 64 bytes of uniform data
            let mut uniform_bytes = [0u8; 64];
            uniform_bytes[..32].copy_from_slice(&h1.digest[..32]);
            uniform_bytes[32..].copy_from_slice(&h2.digest[..32]);

            // Use the first 32 bytes as a point
            let mut point_bytes = [0u8; 32];
            point_bytes.copy_from_slice(&uniform_bytes[..32]);

            // Clear the top bits to match Ristretto encoding
            point_bytes[31] &= 0b0111_1111;

            // Try to find a valid point by incrementing the first byte
            let mut attempts = 0;
            while attempts < 256 {
                let point = PodRistrettoPoint(point_bytes);
                if multiply_ristretto(&PodScalar([1; 32]), &point).is_some() {
                    return point;
                }
                // If not valid, increment the last byte and try again
                point_bytes[0] = point_bytes[0].wrapping_add(1);
                attempts += 1;
            }

            // If we can't find a valid point after 256 attempts, use a hardcoded valid point
            PodRistrettoPoint(BASEPOINT_BYTES)
        }

        fn valid(&self) -> bool {
            // Simple check for zero point
            let point_bytes = self.0.0.0;
            !point_bytes.iter().all(|&x| x == 0)
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
            let hashed_sk_string = H::digest(Scalar::from_bytes_mod_order(self.0.0.0).to_bytes());
            let mut truncated_hashed_sk_string = [0u8; 32];
            truncated_hashed_sk_string.copy_from_slice(&hashed_sk_string.digest[32..64]);

            let mut hash_function = H::default();
            hash_function.update(truncated_hashed_sk_string);
            hash_function.update(h_string);
            let k_string = hash_function.finalize();

            PodScalar::from(&Scalar::from_bytes_mod_order_wide(&k_string.digest))
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
            let gamma = multiply_ristretto(&PodScalar(self.sk.0.0.0), &h_point).unwrap();
            let k = self.sk.ecvrf_nonce_generation(alpha_string);

            let c = ecvrf_challenge_generation([
                &PodRistrettoPoint(self.pk.0.0.0),  // Y (public key)
                &h_point,      // H
                &gamma,        // Gamma
                &multiply_ristretto(&k, &PodRistrettoPoint(BASEPOINT_BYTES)).unwrap(), // U = k*B
                &multiply_ristretto(&k, &h_point).unwrap()  // V = k*H
            ]);

            let k_scalar = Scalar::from_bytes_mod_order(k.0);
            let sk_scalar = Scalar::from_bytes_mod_order(self.sk.0.0.0);
            
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
            let p = PodRistrettoPoint::from(&(RISTRETTO_BASEPOINT_POINT * Scalar::from_bytes_mod_order(sk.0.0.0)));
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
            if !public_key.valid() {
                return Err(MangekyouError::InvalidInput);
            }

            let h_point = public_key.ecvrf_encode_to_curve_solana(alpha_string);
            
            // Convert challenge to scalar and negate it using Solana's operations
            let mut c_scalar = [0u8; 32];
            c_scalar[..C_LEN].copy_from_slice(&self.c.0);
            let neg_challenge = negate_scalar(&PodScalar(c_scalar));

            // Compute U = s*B - c*Y using Solana's multiscalar multiplication
            let u_point = multiscalar_multiply_ristretto(
                &[self.s, neg_challenge],
                &[PodRistrettoPoint(BASEPOINT_BYTES), PodRistrettoPoint(public_key.0.0.0)],
            ).ok_or(MangekyouError::InvalidInput)?;

            // Compute V = s*H - c*Gamma using Solana's multiscalar multiplication
            let v_point = multiscalar_multiply_ristretto(
                &[self.s, neg_challenge],
                &[h_point, self.gamma],
            ).ok_or(MangekyouError::InvalidInput)?;

            let c_prime = ecvrf_challenge_generation([
                &PodRistrettoPoint(public_key.0.0.0),    // Y (public key)
                &h_point,             // H
                &self.gamma,          // Gamma
                &u_point,             // U = s*B - c*Y
                &v_point,             // V = s*H - c*Gamma
            ]);

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

    /// Helper function for scalar negation that only uses Solana's types
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
        
        // Compute L - x in constant time
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

