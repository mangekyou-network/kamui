use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::pubkey::Pubkey;

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct VerifyVrfInput {
    pub alpha_string: Vec<u8>,
    pub proof_bytes: Vec<u8>,
    pub public_key_bytes: Vec<u8>,
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub enum VrfCoordinatorInstruction {
    /// Create a new subscription
    /// Accounts expected:
    /// 0. `[signer]` Subscription owner
    /// 1. `[writable]` Subscription account (PDA)
    /// 2. `[]` System program
    CreateSubscription {
        min_balance: u64,
        confirmations: u8,
    },

    /// Fund a subscription
    /// Accounts expected:
    /// 0. `[signer]` Funder
    /// 1. `[writable]` Subscription account
    /// 2. `[]` System program
    FundSubscription {
        amount: u64,
    },

    /// Request randomness
    /// Accounts expected:
    /// 0. `[signer]` Requester
    /// 1. `[writable]` Request account (PDA)
    /// 2. `[]` Subscription account
    /// 3. `[]` System program
    RequestRandomness {
        seed: [u8; 32],
        callback_data: Vec<u8>,
        num_words: u32,
        minimum_confirmations: u8,
        callback_gas_limit: u64,
    },

    /// Fulfill randomness request
    /// Accounts expected:
    /// 0. `[signer]` Oracle
    /// 1. `[writable]` Request account
    /// 2. `[writable]` VRF result account (PDA)
    /// 3. `[]` Callback program
    /// 4. `[]` System program
    FulfillRandomness {
        proof: Vec<u8>,
        public_key: Vec<u8>,
    },

    /// Cancel a request
    /// Accounts expected:
    /// 0. `[signer]` Request owner
    /// 1. `[writable]` Request account
    CancelRequest,

    /// Register a new oracle
    /// Accounts expected:
    /// 0. `[signer]` Admin
    /// 1. `[writable]` Oracle config account (PDA)
    /// 2. `[]` System program
    RegisterOracle {
        oracle_key: Pubkey,
        vrf_key: [u8; 32],
    },

    /// Deactivate an oracle
    /// Accounts expected:
    /// 0. `[signer]` Admin
    /// 1. `[writable]` Oracle config account
    DeactivateOracle {
        oracle_key: Pubkey,
    },
}

impl VrfCoordinatorInstruction {
    /// Unpacks a byte buffer into a VrfCoordinatorInstruction
    pub fn unpack(input: &[u8]) -> Result<Self, std::io::Error> {
        Self::try_from_slice(input)
    }
} 