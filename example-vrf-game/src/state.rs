use {
    borsh::{BorshDeserialize, BorshSerialize},
    solana_program::{pubkey::Pubkey, program_error::ProgramError},
};

/// State for the game
#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct GameState {
    /// The owner of the game
    pub owner: Pubkey,
    /// The VRF subscription used by this game
    pub subscription: Pubkey,
    /// The current random number (1-100)
    pub current_number: u8,
    /// Whether we're waiting for randomness
    pub is_pending: bool,
}

/// VRF result from the coordinator
#[derive(BorshSerialize, BorshDeserialize)]
pub struct VrfResult {
    /// The randomness outputs
    pub randomness: Vec<[u8; 64]>,
    /// The VRF proof
    pub proof: Vec<u8>,
    /// Block number when proof was generated
    pub proof_block: u64,
}

impl VrfResult {
    pub fn try_deserialize(data: &[u8]) -> Result<Self, ProgramError> {
        // Check discriminator
        if data.len() < 8 || &data[0..8] != b"VRFRSLT\0" {
            return Err(ProgramError::InvalidAccountData);
        }
        // Skip discriminator and deserialize the rest
        Self::try_from_slice(&data[8..]).map_err(|_| ProgramError::InvalidAccountData)
    }
} 