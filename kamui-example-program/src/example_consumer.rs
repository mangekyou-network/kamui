use {
    borsh::{BorshDeserialize, BorshSerialize},
    solana_program::{
        account_info::{next_account_info, AccountInfo},
        entrypoint::ProgramResult,
        msg,
        program::{invoke, invoke_signed},
        program_error::ProgramError,
        pubkey::Pubkey,
        rent::Rent,
        system_instruction,
        sysvar::Sysvar,
    },
    crate::{
        instruction::VrfCoordinatorInstruction,
        state::Subscription,
    },
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
    let system_program = next_account_info(accounts_iter)?;

    if !owner.is_signer {
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

    // Get the exact size needed
    let serialized = borsh::to_vec(&state)?;
    let space = serialized.len();
    msg!("Required space: {}", space);
    msg!("Serialized data: {:?}", serialized);

    let rent = Rent::get()?;
    let lamports = rent.minimum_balance(space);

    msg!("Creating account with {} lamports and {} bytes", lamports, space);

    // Create PDA account with our program as owner
    invoke_signed(
        &system_instruction::create_account(
            owner.key,
            game_state.key,
            lamports,
            space as u64,
            program_id,  // This is the key - setting our program as the owner
        ),
        &[
            owner.clone(),
            game_state.clone(),
            system_program.clone(),
        ],
        &[&[b"game_state", owner.key.as_ref(), &[bump]]],
    )?;

    msg!("Account created with owner: {}", program_id);
    msg!("Account size: {}", game_state.data_len());

    // Initialize the account data
    let mut data = game_state.try_borrow_mut_data()?;
    data[..serialized.len()].copy_from_slice(&serialized);
    msg!("Written data: {:?}", &data[..]);

    msg!("Data initialized");
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

    let mut state = GameState::try_from_slice(&game_state.data.borrow())?;
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

    // Create VRF request
    let seed = rand::random::<[u8; 32]>();
    let request_ix = VrfCoordinatorInstruction::RequestRandomness {
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

    state.is_pending = true;
    let mut data = game_state.try_borrow_mut_data()?;
    let serialized = borsh::to_vec(&state)?;
    data[..serialized.len()].copy_from_slice(&serialized);

    Ok(())
}

fn process_consume_randomness(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let vrf_result = next_account_info(accounts_iter)?;
    let vrf_request = next_account_info(accounts_iter)?;
    let game_state = next_account_info(accounts_iter)?;

    let mut state = GameState::try_from_slice(&game_state.data.borrow())?;
    if !state.is_pending {
        return Err(ProgramError::InvalidAccountData);
    }

    // Extract randomness from VRF result
    let result_data = vrf_result.data.borrow();
    let randomness = result_data[0] as u64 % 100 + 1;
    
    msg!("Received random number: {}", randomness);
    
    // Update game state
    state.current_number = randomness as u8;
    state.is_pending = false;
    state.serialize(&mut *game_state.data.borrow_mut())?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_program_test::*;
    use solana_sdk::{signature::Keypair, signer::Signer};
    use anyhow::Result;
    use std::str::FromStr;

    // Mock VRF program processor
    fn mock_vrf_processor(
        _program_id: &Pubkey,
        _accounts: &[AccountInfo],
        _instruction_data: &[u8],
    ) -> ProgramResult {
        // For testing, just return success
        Ok(())
    }

    #[tokio::test]
    async fn test_game_flow() -> Result<()> {
        // Use a fixed program ID for testing
        let program_id = Pubkey::from_str("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS").unwrap();
        let mut program_test = ProgramTest::new(
            "example_consumer",
            program_id,
            processor!(process_instruction),
        );

        // Add mock VRF program
        let vrf_program_id = Pubkey::new_unique();
        program_test.add_program(
            "vrf_coordinator",
            vrf_program_id,
            processor!(mock_vrf_processor),
        );

        let (mut banks_client, payer, recent_blockhash) = program_test.start().await;

        // Create game state PDA
        let subscription = Keypair::new();
        let (game_state, _bump) = Pubkey::find_program_address(
            &[b"game_state", payer.pubkey().as_ref()],
            &program_id
        );

        // Initialize game
        let ix = GameInstruction::Initialize;
        let ix_data = borsh::to_vec(&ix)?;
        let mut transaction = solana_sdk::transaction::Transaction::new_with_payer(
            &[solana_program::instruction::Instruction {
                program_id,
                accounts: vec![
                    solana_program::instruction::AccountMeta::new(payer.pubkey(), true),
                    solana_program::instruction::AccountMeta::new(game_state, false),
                    solana_program::instruction::AccountMeta::new_readonly(subscription.pubkey(), false),
                    solana_program::instruction::AccountMeta::new_readonly(solana_program::system_program::id(), false),
                ],
                data: ix_data,
            }],
            Some(&payer.pubkey()),
        );
        transaction.sign(&[&payer], recent_blockhash);
        banks_client.process_transaction(transaction).await.unwrap();

        // Verify the account was created correctly
        let game_account = banks_client.get_account(game_state).await.unwrap().unwrap();
        println!("Account owner: {:?}", game_account.owner);
        println!("Account data length: {}", game_account.data.len());
        println!("Account lamports: {}", game_account.lamports);

        // Request random number
        let request_account = Keypair::new();
        let ix = GameInstruction::RequestNewNumber;
        let ix_data = borsh::to_vec(&ix)?;
        let mut transaction = solana_sdk::transaction::Transaction::new_with_payer(
            &[solana_program::instruction::Instruction {
                program_id,
                accounts: vec![
                    solana_program::instruction::AccountMeta::new(payer.pubkey(), true),
                    solana_program::instruction::AccountMeta::new(game_state, false),
                    solana_program::instruction::AccountMeta::new(request_account.pubkey(), false),
                    solana_program::instruction::AccountMeta::new_readonly(subscription.pubkey(), false),
                    solana_program::instruction::AccountMeta::new_readonly(vrf_program_id, false),
                    solana_program::instruction::AccountMeta::new_readonly(solana_program::system_program::id(), false),
                ],
                data: ix_data,
            }],
            Some(&payer.pubkey()),
        );
        transaction.sign(&[&payer], recent_blockhash);
        banks_client.process_transaction(transaction).await.unwrap();

        // Get a new blockhash to ensure we're not reusing the old one
        let recent_blockhash = banks_client.get_latest_blockhash().await?;

        // Verify game state is pending
        let game_account = banks_client
            .get_account(game_state)
            .await
            .unwrap()
            .unwrap();
        
        println!("Account owner after request: {:?}", game_account.owner);
        println!("Account data length: {}", game_account.data.len());
        println!("Account data: {:?}", game_account.data);
        
        match GameState::try_from_slice(&game_account.data) {
            Ok(game_state) => {
                println!("Successfully deserialized game state: {:?}", game_state);
                assert!(game_state.is_pending);
            }
            Err(e) => {
                println!("Failed to deserialize game state: {:?}", e);
                println!("First few bytes: {:?}", &game_account.data[..8.min(game_account.data.len())]);
                return Err(anyhow::anyhow!("Failed to deserialize: {}", e));
            }
        }

        Ok(())
    }
} 