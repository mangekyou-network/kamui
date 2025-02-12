use {
    borsh::{BorshDeserialize, BorshSerialize},
    solana_program::pubkey::Pubkey,
};

/// Constants for request validation
pub const MINIMUM_REQUEST_CONFIRMATIONS: u8 = 1;
pub const MAXIMUM_REQUEST_CONFIRMATIONS: u8 = 255;
pub const MINIMUM_CALLBACK_GAS_LIMIT: u64 = 10_000;
pub const MAXIMUM_CALLBACK_GAS_LIMIT: u64 = 1_000_000;
pub const MAXIMUM_RANDOM_WORDS: u32 = 100;

#[derive(BorshSerialize, BorshDeserialize, Debug, PartialEq)]
pub enum RequestStatus {
    Pending,
    Fulfilled,
    Cancelled,
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct Subscription {
    /// The owner of this subscription
    pub owner: Pubkey,
    /// Current balance for VRF requests
    pub balance: u64,
    /// Minimum balance required for requests
    pub min_balance: u64,
    /// Number of confirmations required before generating VRF proof
    pub confirmations: u8,
    /// Nonce for request ID generation
    pub nonce: u64,
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct RandomnessRequest {
    /// The subscription this request belongs to
    pub subscription: Pubkey,
    /// The seed used for randomness
    pub seed: [u8; 32],
    /// The requester's program ID that will receive the callback
    pub requester: Pubkey,
    /// The callback function data
    pub callback_data: Vec<u8>,
    /// Block number when request was made
    pub request_block: u64,
    /// Status of the request
    pub status: RequestStatus,
    /// Number of random words requested
    pub num_words: u32,
    /// Maximum compute units for callback
    pub callback_gas_limit: u64,
    /// Request nonce from subscription
    pub nonce: u64,
    /// Commitment hash of request parameters
    pub commitment: [u8; 32],
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct VrfResult {
    /// The randomness outputs
    pub randomness: Vec<[u8; 64]>,
    /// The VRF proof
    pub proof: Vec<u8>,
    /// Block number when proof was generated
    pub proof_block: u64,
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct OracleConfig {
    /// The oracle's public key
    pub oracle_key: Pubkey,
    /// The oracle's VRF public key
    pub vrf_key: [u8; 32],
    /// Whether the oracle is active
    pub is_active: bool,
} 