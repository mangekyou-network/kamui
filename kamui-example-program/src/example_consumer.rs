use {
    borsh::{BorshDeserialize, BorshSerialize},
    crate::{
        instruction::VrfCoordinatorInstruction,
        state::{RandomnessRequest, Subscription},
    },
    solana_program::{
        account_info::{next_account_info, AccountInfo},
        entrypoint::ProgramResult,
        msg,
        program::invoke,
        program_error::ProgramError,
        pubkey::Pubkey,
        system_instruction,
        sysvar::{rent::Rent, Sysvar},
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

    let state = GameState {
        owner: *owner.key,
        subscription: *subscription.key,
        current_number: 0,
        is_pending: false,
    };

    // Create game state account
    let rent = Rent::get()?;
    let space = borsh::to_vec(&state)?.len();
    let lamports = rent.minimum_balance(space);

    invoke(
        &system_instruction::create_account(
            owner.key,
            game_state.key,
            lamports,
            space as u64,
            program_id,
        ),
        &[owner.clone(), game_state.clone(), system_program.clone()],
    )?;

    state.serialize(&mut *game_state.data.borrow_mut())?;
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

    let mut state = GameState::try_from_slice(&game_state.data.borrow())?;
    if state.owner != *owner.key {
        return Err(ProgramError::InvalidAccountData);
    }
    if state.is_pending {
        return Err(ProgramError::InvalidAccountData);
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
                solana_program::instruction::AccountMeta::new(*request_account.key, false),
                solana_program::instruction::AccountMeta::new_readonly(*subscription.key, false),
                solana_program::instruction::AccountMeta::new_readonly(*system_program.key, false),
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
    state.serialize(&mut *game_state.data.borrow_mut())?;

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

    #[tokio::test]
    async fn test_game_flow() -> Result<()> {
        let program_id = Pubkey::new_unique();
        let mut program_test = ProgramTest::new(
            "example_consumer",
            program_id,
            processor!(process_instruction),
        );

        let (mut banks_client, payer, recent_blockhash) = program_test.start().await;

        // Create game state account
        let game_state = Keypair::new();
        let subscription = Keypair::new();

        // Initialize game
        let ix = GameInstruction::Initialize;
        let ix_data = borsh::to_vec(&ix)?;
        let mut transaction = solana_sdk::transaction::Transaction::new_with_payer(
            &[solana_program::instruction::Instruction {
                program_id,
                accounts: vec![
                    solana_program::instruction::AccountMeta::new(payer.pubkey(), true),
                    solana_program::instruction::AccountMeta::new(game_state.pubkey(), false),
                    solana_program::instruction::AccountMeta::new_readonly(subscription.pubkey(), false),
                    solana_program::instruction::AccountMeta::new_readonly(solana_program::system_program::id(), false),
                ],
                data: ix_data,
            }],
            Some(&payer.pubkey()),
        );
        transaction.sign(&[&payer], recent_blockhash);
        banks_client.process_transaction(transaction).await.unwrap();

        // Request random number
        let request_account = Keypair::new();
        let vrf_program = Keypair::new();

        let ix = GameInstruction::RequestNewNumber;
        let ix_data = borsh::to_vec(&ix)?;
        let mut transaction = solana_sdk::transaction::Transaction::new_with_payer(
            &[solana_program::instruction::Instruction {
                program_id,
                accounts: vec![
                    solana_program::instruction::AccountMeta::new(payer.pubkey(), true),
                    solana_program::instruction::AccountMeta::new(game_state.pubkey(), false),
                    solana_program::instruction::AccountMeta::new(request_account.pubkey(), false),
                    solana_program::instruction::AccountMeta::new_readonly(subscription.pubkey(), false),
                    solana_program::instruction::AccountMeta::new_readonly(vrf_program.pubkey(), false),
                    solana_program::instruction::AccountMeta::new_readonly(solana_program::system_program::id(), false),
                ],
                data: ix_data,
            }],
            Some(&payer.pubkey()),
        );
        transaction.sign(&[&payer], recent_blockhash);
        banks_client.process_transaction(transaction).await.unwrap();

        // Verify game state is pending
        let game_account = banks_client
            .get_account(game_state.pubkey())
            .await
            .unwrap()
            .unwrap();
        let game_state = GameState::try_from_slice(&game_account.data).unwrap();
        assert!(game_state.is_pending);

        Ok(())
    }
} 