use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
};
use borsh::{BorshDeserialize, BorshSerialize};
use solana_zk_token_sdk::curve25519::{
    ristretto::*,
    scalar::*,
};
use sha2::{Sha512, Digest};

/// The suite string for the VRF as defined in the spec
const SUITE_STRING: &[u8; 7] = b"sol_vrf";

/// Length of challenges in bytes
const C_LEN: usize = 16;

/// The hash function used for the VRF
type H = Sha512;

/// The Ristretto basepoint encoded as bytes
const BASEPOINT_BYTES: [u8; 32] = [
    0xe2, 0xf2, 0xae, 0x0a, 0x6a, 0xbc, 0x4e, 0x71,
    0xa8, 0x84, 0xa9, 0x61, 0xc5, 0x00, 0x51, 0x5f,
    0x58, 0xe3, 0x0b, 0x6a, 0xa5, 0x82, 0xdd, 0x8d,
    0xb6, 0xa6, 0x59, 0x45, 0xe0, 0x8d, 0x2d, 0x76,
];

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct VerifyVrfInput {
    pub alpha_string: Vec<u8>,
    pub proof_bytes: Vec<u8>,
    pub public_key_bytes: Vec<u8>,
}

#[derive(Debug)]
pub struct ECVRFProof {
    gamma: PodRistrettoPoint,
    c: [u8; C_LEN],
    s: PodScalar,
}

impl ECVRFProof {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProgramError> {
        if bytes.len() != 80 {  // 32 + 16 + 32
            return Err(ProgramError::InvalidInstructionData);
        }

        let mut gamma = [0u8; 32];
        let mut c = [0u8; C_LEN];
        let mut s = [0u8; 32];

        gamma.copy_from_slice(&bytes[0..32]);
        c.copy_from_slice(&bytes[32..32+C_LEN]);  // Challenge is 16 bytes
        s.copy_from_slice(&bytes[32+C_LEN..80]);  // Last 32 bytes are the scalar

        Ok(Self {
            gamma: PodRistrettoPoint(gamma),
            c,
            s: PodScalar(s),
        })
    }

    fn ecvrf_encode_to_curve_solana(alpha_string: &[u8]) -> PodRistrettoPoint {
        // Constants for expand_message_xmd
        const B_IN_BYTES: usize = 64;  // SHA-512 output size
        const DST: &[u8] = b"ECVRF_ristretto255_XMD:SHA-512_R255MAP_RO_sol_vrf";
        const LEN_IN_BYTES: usize = 64;  // We want 64 bytes of output

        // Compute b_0 = H(Z_pad || msg || len || DST || DST_len)
        let mut hasher = H::default();
        // Z_pad is a block of zeros
        hasher.update(&[0u8; 128]);  // SHA-512 block size is 128 bytes
        hasher.update(alpha_string);
        hasher.update(&[(LEN_IN_BYTES >> 8) as u8, LEN_IN_BYTES as u8]);
        hasher.update(DST);
        hasher.update(&[DST.len() as u8]);
        let b_0 = hasher.finalize();

        // Compute b_1 = H(b_0 || 0x01 || DST || DST_len)
        let mut hasher = H::default();
        hasher.update(&b_0);
        hasher.update(&[1u8]);
        hasher.update(DST);
        hasher.update(&[DST.len() as u8]);
        let b_1 = hasher.finalize();

        // Compute b_2 = H((b_0 xor b_1) || 0x02 || DST || DST_len)
        let mut tmp = [0u8; B_IN_BYTES];
        for i in 0..B_IN_BYTES {
            tmp[i] = b_0[i] ^ b_1[i];
        }
        let mut hasher = H::default();
        hasher.update(&tmp);
        hasher.update(&[2u8]);
        hasher.update(DST);
        hasher.update(&[DST.len() as u8]);
        let b_2 = hasher.finalize();

        // Combine b_1 and b_2 to get uniform bytes
        let mut uniform_bytes = [0u8; 64];
        uniform_bytes[..32].copy_from_slice(&b_1[..32]);
        uniform_bytes[32..].copy_from_slice(&b_2[..32]);

        // Map to curve point
        let mut point_bytes = [0u8; 32];
        point_bytes.copy_from_slice(&uniform_bytes[..32]);
        point_bytes[31] &= 0b0111_1111;  // Clear top bit

        // Try to find a valid point
        let mut attempts = 0;
        while attempts < 256 {
            let point = PodRistrettoPoint(point_bytes);
            if multiply_ristretto(&PodScalar([1; 32]), &point).is_some() {
                return point;
            }
            point_bytes[0] = point_bytes[0].wrapping_add(1);
            attempts += 1;
        }

        // If no valid point found, use the basepoint
        PodRistrettoPoint(BASEPOINT_BYTES)
    }

    fn ecvrf_challenge_generation(points: [&PodRistrettoPoint; 5]) -> [u8; C_LEN] {
        let mut hasher = H::default();
        hasher.update(SUITE_STRING);
        hasher.update([0x02]); // challenge_generation_domain_separator_front
        for p in points.iter() {
            hasher.update(p.0);
        }
        hasher.update([0x00]); // challenge_generation_domain_separator_back
        let digest = hasher.finalize();

        let mut challenge_bytes = [0u8; C_LEN];
        challenge_bytes.copy_from_slice(&digest[..C_LEN]);
        challenge_bytes
    }

    pub fn verify(&self, alpha_string: &[u8], public_key: &PodRistrettoPoint) -> Result<(), ProgramError> {
        // Ensure the public key is valid (not zero)
        if public_key.0.iter().all(|&x| x == 0) {
            msg!("Invalid public key: zero point");
            return Err(ProgramError::InvalidArgument);
        }

        // Encode the input alpha_string to a curve point
        let h_point = Self::ecvrf_encode_to_curve_solana(alpha_string);

        // Convert challenge to scalar and negate it
        let mut c_scalar = [0u8; 32];
        c_scalar[..C_LEN].copy_from_slice(&self.c);
        let neg_challenge = negate_scalar(&PodScalar(c_scalar));

        // Compute U = s*B - c*Y using multiscalar multiplication
        let u_point = multiscalar_multiply_ristretto(
            &[self.s, neg_challenge],
            &[PodRistrettoPoint(BASEPOINT_BYTES), *public_key],
        ).ok_or(ProgramError::InvalidArgument)?;

        // Compute V = s*H - c*Gamma using multiscalar multiplication
        let v_point = multiscalar_multiply_ristretto(
            &[self.s, neg_challenge],
            &[h_point, self.gamma],
        ).ok_or(ProgramError::InvalidArgument)?;

        // Recompute the challenge
        let c_prime = Self::ecvrf_challenge_generation([
            public_key,
            &h_point,
            &self.gamma,
            &u_point,
            &v_point,
        ]);

        // Check if the recomputed challenge matches the original challenge
        if c_prime != self.c {
            msg!("Challenge verification failed");
            return Err(ProgramError::InvalidArgument);
        }

        msg!("VRF proof verification successful!");
        Ok(())
    }

    pub fn to_hash(&self) -> [u8; 64] {
        let mut hash = H::default();
        hash.update(SUITE_STRING);
        hash.update([0x03]); // proof_to_hash_domain_separator_front
        hash.update(self.gamma.0);
        hash.update([0x00]); // proof_to_hash_domain_separator_back
        let mut output = [0u8; 64];
        output.copy_from_slice(&hash.finalize()[..64]);
        output
    }
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

entrypoint!(process_instruction);

pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let _payer_account = next_account_info(accounts_iter)?;

    let input = VerifyVrfInput::try_from_slice(instruction_data)
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    
    // Deserialize the proof and public key from bytes
    let proof = ECVRFProof::from_bytes(&input.proof_bytes)?;
    
    if input.public_key_bytes.len() != 32 {
        msg!("Invalid public key length");
        return Err(ProgramError::InvalidInstructionData);
    }
    
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&input.public_key_bytes);
    let public_key = PodRistrettoPoint(public_key);
    
    // Verify the proof
    proof.verify(&input.alpha_string, &public_key)?;

    // If verification succeeds, compute and log the VRF output
    let vrf_output = proof.to_hash();
    msg!("VRF output: {:?}", vrf_output);
    
    Ok(())
}
