use {
    borsh::{BorshDeserialize, BorshSerialize},
    solana_program::{
        account_info::{next_account_info, AccountInfo},
        entrypoint::ProgramResult,
        msg,
        program::{invoke, invoke_signed},
        pubkey::Pubkey,
        system_instruction,
        system_program,
        program_error::ProgramError,
        sysvar::{Sysvar, rent::Rent},
    },
    std::str::FromStr,
    crate::{
        instruction::VrfCoordinatorInstruction,
        state::{VrfResult, Subscription},
    },
};

#[cfg(feature = "mock")]
use {
    solana_program::{
        account_info::AccountInfo,
        entrypoint::ProgramResult,
        msg,
        program::invoke,
        pubkey::Pubkey,
        system_program,
    },
    rand,
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

/// Instructions for the game
#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub enum GameInstruction {
    /// Initialize the game
    /// Accounts expected:
    /// 0. `[signer]` Game owner
    /// 1. `[writable]` Game state account (PDA)
    /// 2. `[]` VRF subscription account
    /// 3. `[]` System program
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

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let instruction = GameInstruction::try_from_slice(instruction_data)?;

    match instruction {
        GameInstruction::Initialize => process_initialize(program_id, accounts),
        GameInstruction::RequestNewNumber => process_request_number(program_id, accounts),
        GameInstruction::ConsumeRandomness => process_consume_randomness(program_id, accounts),
    }
}

fn process_initialize(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let owner = next_account_info(accounts_iter)?;
    let game_state = next_account_info(accounts_iter)?;
    let subscription = next_account_info(accounts_iter)?;
    let payer = next_account_info(accounts_iter)?;
    let system_program = next_account_info(accounts_iter)?;

    if !owner.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !payer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Verify game state PDA
    let (expected_game_state, bump) = Pubkey::find_program_address(
        &[b"game_state", owner.key.as_ref()],
        program_id
    );
    if expected_game_state != *game_state.key {
        return Err(ProgramError::InvalidSeeds);
    }

    let state = GameState {
        owner: *owner.key,
        subscription: *subscription.key,
        current_number: 0,
        is_pending: false,
    };

    // Create game state account
    let space = 8 + borsh::to_vec(&state)?.len();
    let rent = Rent::get()?;
    let lamports = rent.minimum_balance(space);

    invoke_signed(
        &system_instruction::create_account(
            payer.key,
            game_state.key,
            lamports,
            space as u64,
            program_id,
        ),
        &[payer.clone(), game_state.clone(), system_program.clone()],
        &[&[b"game_state", owner.key.as_ref(), &[bump]]],
    )?;

    // Write discriminator and state
    let mut data = game_state.try_borrow_mut_data()?;
    data[0..8].copy_from_slice(&[71, 65, 77, 69, 83, 84, 65, 84]); // "GAMESTAT" as bytes
    state.serialize(&mut &mut data[8..])?;

    Ok(())
}

fn process_request_number(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let owner = next_account_info(accounts_iter)?;
    let game_state = next_account_info(accounts_iter)?;
    let request_account = next_account_info(accounts_iter)?;
    let subscription = next_account_info(accounts_iter)?;
    let vrf_program = next_account_info(accounts_iter)?;
    let system_program = next_account_info(accounts_iter)?;

    if !owner.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Verify game state account owner
    if game_state.owner != program_id {
        return Err(ProgramError::IllegalOwner);
    }

    // Verify game state PDA
    let (expected_game_state, _bump) = Pubkey::find_program_address(
        &[b"game_state", owner.key.as_ref()],
        program_id
    );
    if expected_game_state != *game_state.key {
        return Err(ProgramError::InvalidSeeds);
    }

    // Verify discriminator
    let data = game_state.data.borrow();
    if data[0..8] != [71, 65, 77, 69, 83, 84, 65, 84] {  // "GAMESTAT" as bytes
        return Err(ProgramError::InvalidAccountData);
    }

    let mut state = GameState::try_from_slice(&data[8..])?;  // Skip discriminator
    if state.owner != *owner.key {
        return Err(ProgramError::InvalidAccountData);
    }
    if state.is_pending {
        return Err(ProgramError::InvalidAccountData);
    }

    // Read the subscription account to get the current nonce
    let subscription_data = subscription.try_borrow_data()?;
    let subscription_state = Subscription::try_from_slice(&subscription_data[8..])?;
    let next_nonce = subscription_state.nonce.checked_add(1).unwrap();

    // Derive the request account PDA
    let (request_pda, _bump) = Pubkey::find_program_address(
        &[
            b"request",
            subscription.key.as_ref(),
            &next_nonce.to_le_bytes(),
        ],
        vrf_program.key
    );

    if request_pda != *request_account.key {
        return Err(ProgramError::InvalidSeeds);
    }

    // Create VRF request with a deterministic seed
    let seed = [0u8; 32]; // Use a deterministic seed for on-chain code
    let request_ix = VrfCoordinatorInstruction::RequestRandomness {
        seed,
        callback_data: borsh::to_vec(&GameInstruction::ConsumeRandomness)?,
        num_words: 1,
        minimum_confirmations: 1,
        callback_gas_limit: 200_000,
    };

    // Add discriminator bytes for VrfCoordinatorInstruction
    let mut request_ix_data = vec![0u8; 8];
    request_ix_data[0..8].copy_from_slice(b"VRFREQST");
    request_ix_data.extend(borsh::to_vec(&request_ix)?);

    invoke(
        &solana_program::instruction::Instruction {
            program_id: *vrf_program.key,
            accounts: vec![
                solana_program::instruction::AccountMeta::new(*owner.key, true),
                solana_program::instruction::AccountMeta::new(request_pda, false),
                solana_program::instruction::AccountMeta::new_readonly(*subscription.key, false),
                solana_program::instruction::AccountMeta::new_readonly(solana_program::system_program::id(), false),
            ],
            data: request_ix_data,
        },
        &[
            owner.clone(),
            request_account.clone(),
            subscription.clone(),
            system_program.clone(),
        ],
    )?;

    // Update and write back game state
    state.is_pending = true;
    let mut data = game_state.try_borrow_mut_data()?;
    state.serialize(&mut &mut data[8..])?;

    Ok(())
}

pub fn process_consume_randomness(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let vrf_result = next_account_info(accounts_iter)?;
    let request_account = next_account_info(accounts_iter)?;
    let game_state = next_account_info(accounts_iter)?;

    // Verify game state account owner
    if game_state.owner != program_id {
        return Err(ProgramError::IllegalOwner);
    }

    // Verify discriminator
    let data = game_state.data.borrow();
    if data[0..8] != [71, 65, 77, 69, 83, 84, 65, 84] {  // "GAMESTAT" as bytes
        return Err(ProgramError::InvalidAccountData);
    }

    // Deserialize the game state first to get the owner
    let state = GameState::try_from_slice(&data[8..])?;

    // Verify game state PDA
    let (expected_game_state, _bump) = Pubkey::find_program_address(
        &[b"game_state", state.owner.as_ref()],
        program_id
    );
    if expected_game_state != *game_state.key {
        return Err(ProgramError::InvalidSeeds);
    }

    // Get VRF coordinator program ID
    let vrf_coordinator_id = Pubkey::from_str("29wLw7e3ZsxrMBorrm37abTyzX9wUesxy1tiBmwDqrso").unwrap();

    // Verify VRF result account owner
    if vrf_result.owner != &vrf_coordinator_id {
        return Err(ProgramError::IllegalOwner);
    }

    // Verify request account owner
    if request_account.owner != &vrf_coordinator_id {
        return Err(ProgramError::IllegalOwner);
    }

    // Verify VRF result PDA
    let (expected_vrf_result, _) = Pubkey::find_program_address(
        &[b"vrf_result", request_account.key.as_ref()],
        &vrf_coordinator_id
    );
    if expected_vrf_result != *vrf_result.key {
        return Err(ProgramError::InvalidSeeds);
    }

    // Deserialize the VRF result
    let vrf_result_data = VrfResult::try_from_slice(&vrf_result.data.borrow()[8..])?;

    // Ensure we have at least one randomness value
    if vrf_result_data.randomness.is_empty() {
        return Err(ProgramError::InvalidAccountData);
    }

    // Take the first 8 bytes of the first randomness value and convert to u64
    let random_bytes = &vrf_result_data.randomness[0][0..8];
    let random_value = u64::from_le_bytes(random_bytes.try_into().unwrap());
    
    // Update game state with new random number (1-100)
    let mut state = state;  // Make state mutable
    state.current_number = ((random_value % 100) + 1) as u8;
    state.is_pending = false;

    // Write back the updated state (skip discriminator)
    let mut data = game_state.try_borrow_mut_data()?;
    state.serialize(&mut &mut data[8..])?;

    Ok(())
}

#[cfg(feature = "mock")]
pub fn request_randomness(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
) -> ProgramResult {
    let seed = rand::random::<[u8; 32]>();
    // ... rest of the code ...
    Ok(())
}

#[cfg(feature = "mock")]
pub fn consume_randomness(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
) -> ProgramResult {
    // ... rest of the code ...
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_sdk::{signature::Keypair, signer::Signer};
    use anyhow::Result;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_game_flow() -> Result<()> {
        // Use a fixed program ID for testing
        let program_id = Pubkey::from_str("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS").unwrap();

        // Create test accounts
        let payer = Keypair::new();
        let subscription = Keypair::new();
        let (game_state, _bump) = Pubkey::find_program_address(
            &[b"game_state", payer.pubkey().as_ref()],
            &program_id
        );

        // Initialize game state
        let state = GameState {
            owner: payer.pubkey(),
            subscription: subscription.pubkey(),
            current_number: 0,
            is_pending: false,
        };

        // Verify the state can be serialized and deserialized
        let mut data = vec![0u8; 8 + borsh::to_vec(&state)?.len()];
        data[0..8].copy_from_slice(b"GAMESTAT");
        state.serialize(&mut &mut data[8..])?;
        
        let deserialized_state = GameState::try_from_slice(&data[8..])?;
        assert_eq!(deserialized_state.owner, state.owner);
        assert_eq!(deserialized_state.subscription, state.subscription);
        assert_eq!(deserialized_state.current_number, state.current_number);
        assert_eq!(deserialized_state.is_pending, state.is_pending);

        Ok(())
    }
} 