use borsh::{BorshDeserialize, BorshSerialize};

/// Instructions for the game
#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub enum GameInstruction {
    /// Initialize the game
    /// Accounts expected:
    /// 0. `[signer]` Game owner
    /// 1. `[writable]` Game state account (PDA)
    /// 2. `[]` VRF subscription account
    /// 3. `[signer]` Payer for account creation
    /// 4. `[]` System program
    Initialize,

    /// Request a new random number
    /// Accounts expected:
    /// 0. `[signer]` Game owner
    /// 1. `[writable]` Game state account
    /// 2. `[writable]` VRF request account (PDA)
    /// 3. `[]` VRF subscription account
    /// 4. `[]` VRF coordinator program
    /// 5. `[]` System program
    RequestNewNumber,

    /// Consume randomness callback from VRF
    /// Accounts expected:
    /// 0. `[]` VRF result account
    /// 1. `[]` VRF request account
    /// 2. `[writable]` Game state account
    ConsumeRandomness,
} 