use {
    crate::{
        error::GameError,
        instruction::GameInstruction,
        state::{GameState, VrfResult},
    },
    borsh::{BorshDeserialize, BorshSerialize},
    solana_program::{
        account_info::{next_account_info, AccountInfo},
        entrypoint::ProgramResult,
        msg,
        program::{invoke, invoke_signed},
        program_error::ProgramError,
        pubkey::Pubkey,
        system_instruction,
        sysvar::{Sysvar, rent::Rent},
    },
    std::str::FromStr,
};

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    msg!("Game Program: Processing instruction");
    let instruction = GameInstruction::try_from_slice(instruction_data)
        .map_err(|e| {
            msg!("Game Program: Failed to deserialize instruction: {}", e);
            ProgramError::InvalidInstructionData
        })?;

    match instruction {
        GameInstruction::Initialize => {
            msg!("Game Program: Initialize instruction");
            process_initialize(program_id, accounts)
        }
        GameInstruction::RequestNewNumber => {
            msg!("Game Program: RequestNewNumber instruction");
            process_request_number(program_id, accounts)
        }
        GameInstruction::ConsumeRandomness => {
            msg!("Game Program: ConsumeRandomness instruction");
            process_consume_randomness(program_id, accounts)
        }
    }
}

fn process_initialize(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    msg!("Game Program: Processing initialize");
    let accounts_iter = &mut accounts.iter();
    let owner = next_account_info(accounts_iter)?;
    let game_state = next_account_info(accounts_iter)?;
    let subscription = next_account_info(accounts_iter)?;
    let payer = next_account_info(accounts_iter)?;
    let system_program = next_account_info(accounts_iter)?;

    msg!("Game Program: Owner: {}", owner.key);
    msg!("Game Program: Game state: {}", game_state.key);
    msg!("Game Program: Subscription: {}", subscription.key);
    msg!("Game Program: Payer: {}", payer.key);

    if !owner.is_signer {
        msg!("Game Program: Error - Missing owner signature");
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !payer.is_signer {
        msg!("Game Program: Error - Missing payer signature");
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Verify game state PDA
    let (expected_game_state, bump) = Pubkey::find_program_address(
        &[b"game_state", owner.key.as_ref()],
        program_id
    );
    msg!("Game Program: Expected game state: {}", expected_game_state);
    
    if expected_game_state != *game_state.key {
        msg!("Game Program: Error - Invalid game state PDA");
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

    msg!("Game Program: Creating game state account - space: {}, lamports: {}", space, lamports);

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

    msg!("Game Program: Writing game state data");
    // Write discriminator and state
    let mut data = game_state.try_borrow_mut_data()?;
    data[0..8].copy_from_slice(b"GAMESTAT");
    state.serialize(&mut &mut data[8..])
        .map_err(|e| {
            msg!("Game Program: Failed to serialize game state: {}", e);
            ProgramError::InvalidAccountData
        })?;

    msg!("Game Program: Initialize completed successfully");
    Ok(())
}

fn process_request_number(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    msg!("Game Program: Processing request number");
    let accounts_iter = &mut accounts.iter();
    let owner = next_account_info(accounts_iter)?;
    let game_state = next_account_info(accounts_iter)?;
    let request_account = next_account_info(accounts_iter)?;
    let subscription = next_account_info(accounts_iter)?;
    let vrf_program = next_account_info(accounts_iter)?;
    let system_program = next_account_info(accounts_iter)?;

    msg!("Game Program: Owner: {}", owner.key);
    msg!("Game Program: Game state: {}", game_state.key);
    msg!("Game Program: Request account: {}", request_account.key);
    msg!("Game Program: Subscription: {}", subscription.key);
    msg!("Game Program: VRF program: {}", vrf_program.key);

    if !owner.is_signer {
        msg!("Game Program: Error - Missing owner signature");
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
    if data[0..8] != *b"GAMESTAT" {
        return Err(ProgramError::InvalidAccountData);
    }

    let mut state = GameState::try_from_slice(&data[8..])?;  // Skip discriminator
    if state.owner != *owner.key {
        return Err(GameError::InvalidOwner.into());
    }
    if state.is_pending {
        return Err(GameError::AlreadyPending.into());
    }

    // Create VRF request with a deterministic seed
    let seed = [0u8; 32]; // Use a deterministic seed for on-chain code
    let request_ix = VrfCpi::RequestRandomness {
        seed,
        callback_data: borsh::to_vec(&GameInstruction::ConsumeRandomness)?,
        num_words: 1,
        minimum_confirmations: 1,
        callback_gas_limit: 200_000,
    };

    let request_ix_data = borsh::to_vec(&request_ix)?;
    invoke(
        &solana_program::instruction::Instruction {
            program_id: *vrf_program.key,
            accounts: vec![
                solana_program::instruction::AccountMeta::new(*owner.key, true),
                solana_program::instruction::AccountMeta::new(*request_account.key, false),
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

fn process_consume_randomness(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    msg!("Game Program: Starting ConsumeRandomness");
    let accounts_iter = &mut accounts.iter();
    let vrf_result = next_account_info(accounts_iter)?;
    let request_account = next_account_info(accounts_iter)?;
    let game_state = next_account_info(accounts_iter)?;

    msg!("Game Program: VRF result account: {}", vrf_result.key);
    msg!("Game Program: Request account: {}", request_account.key);
    msg!("Game Program: Game state account: {}", game_state.key);
    msg!("Game Program: Game state owner: {}", game_state.owner);
    msg!("Game Program: Game state is writable: {}", game_state.is_writable);
    msg!("Game Program: Program ID: {}", program_id);

    // Verify game state account owner
    if game_state.owner != program_id {
        msg!("Game Program: Error - Invalid game state owner. Expected {}, got {}", program_id, game_state.owner);
        return Err(ProgramError::IllegalOwner);
    }

    // Verify discriminator and deserialize state
    let state = {
        let data = game_state.data.borrow();
        msg!("Game Program: Checking discriminator");
        if data[0..8] != *b"GAMESTAT" {
            msg!("Game Program: Error - Invalid discriminator");
            return Err(ProgramError::InvalidAccountData);
        }
        msg!("Game Program: Deserializing game state");
        GameState::try_from_slice(&data[8..])?
    };

    // Verify game state PDA and ownership
    let (expected_game_state, bump) = Pubkey::find_program_address(
        &[b"game_state", state.owner.as_ref()],
        program_id
    );
    if expected_game_state != *game_state.key {
        msg!("Game Program: Error - Invalid game state PDA. Expected {}, got {}", expected_game_state, game_state.key);
        return Err(ProgramError::InvalidSeeds);
    }

    // Get VRF coordinator program ID
    let vrf_coordinator_id = Pubkey::from_str("BfwfooykCSdb1vgu6FcP75ncUgdcdt4ciUaeaSLzxM4D").unwrap();
    msg!("Game Program: VRF coordinator ID: {}", vrf_coordinator_id);

    // Verify VRF result account owner
    if vrf_result.owner != &vrf_coordinator_id {
        msg!("Game Program: Error - Invalid VRF result owner. Expected {}, got {}", vrf_coordinator_id, vrf_result.owner);
        return Err(GameError::InvalidVrfCoordinator.into());
    }

    // Verify request account owner
    if request_account.owner != &vrf_coordinator_id {
        msg!("Game Program: Error - Invalid request account owner. Expected {}, got {}", vrf_coordinator_id, request_account.owner);
        return Err(GameError::InvalidVrfCoordinator.into());
    }

    // Verify VRF result PDA
    let (expected_vrf_result, _) = Pubkey::find_program_address(
        &[b"vrf_result", request_account.key.as_ref()],
        &vrf_coordinator_id
    );
    if expected_vrf_result != *vrf_result.key {
        msg!("Game Program: Error - Invalid VRF result PDA. Expected {}, got {}", expected_vrf_result, vrf_result.key);
        return Err(GameError::InvalidVrfResult.into());
    }

    // Deserialize the VRF result with discriminator check
    msg!("Game Program: Deserializing VRF result");
    let vrf_result_data = VrfResult::try_deserialize(&vrf_result.data.borrow())?;

    // Ensure we have at least one randomness value
    if vrf_result_data.randomness.is_empty() {
        msg!("Game Program: Error - VRF result has no randomness values");
        return Err(ProgramError::InvalidAccountData);
    }

    // Take the first 8 bytes of the first randomness value and convert to u64
    let random_bytes = &vrf_result_data.randomness[0][0..8];
    let random_value = u64::from_le_bytes(random_bytes.try_into().unwrap());
    msg!("Game Program: Generated random value: {}", random_value);
    
    // Update game state with new random number (1-100)
    let mut updated_state = state;
    updated_state.current_number = ((random_value % 100) + 1) as u8;
    updated_state.is_pending = false;
    msg!("Game Program: New random number: {}", updated_state.current_number);

    // Write back the updated state (skip discriminator)
    msg!("Game Program: Writing updated state");
    let mut data = game_state.try_borrow_mut_data()?;
    updated_state.serialize(&mut &mut data[8..])?;
    msg!("Game Program: State updated successfully");

    Ok(())
}

#[derive(BorshSerialize)]
enum VrfCpi {
    RequestRandomness {
        seed: [u8; 32],
        callback_data: Vec<u8>,
        num_words: u32,
        minimum_confirmations: u8,
        callback_gas_limit: u64,
    },
} 