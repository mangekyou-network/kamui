use {
    borsh::{BorshSerialize, BorshDeserialize},
    kamui_example_program::{
        instruction::VrfCoordinatorInstruction,
        state::{Subscription, RandomnessRequest, RequestStatus},
        example_consumer::{GameState, GameInstruction},
        mock_prover::MockProver,
    },
    solana_program::{
        instruction::{AccountMeta, Instruction},
        pubkey::Pubkey,
        system_program,
        system_instruction,
    },
    solana_program_test::*,
    solana_sdk::{
        signature::Keypair,
        signer::Signer,
        transaction::Transaction,
        hash::Hash,
    },
    spl_token::native_mint,
    spl_associated_token_account,
};

async fn setup_test() -> (BanksClient, Keypair, Hash, Pubkey, Pubkey) {
    // Setup VRF coordinator program
    let vrf_program_id = Pubkey::new_unique();
    let mut program_test = ProgramTest::new(
        "kamui_example_program",
        vrf_program_id,
        processor!(kamui_example_program::process_instruction),
    );

    // Setup game program
    let game_program_id = Pubkey::new_unique();
    program_test.add_program(
        "example_consumer",
        game_program_id,
        processor!(kamui_example_program::example_consumer::process_instruction),
    );

    // Add SPL Token program
    program_test.add_program(
        "spl_token",
        spl_token::id(),
        processor!(spl_token::processor::Processor::process),
    );

    let (mut banks_client, payer, recent_blockhash) = program_test.start().await;
    
    (banks_client, payer, recent_blockhash, vrf_program_id, game_program_id)
}

#[tokio::test]
async fn test_vrf_flow() -> Result<(), Box<dyn std::error::Error>> {
    // Create program test environment
    let game_program_id = Pubkey::new_unique();
    let mut program_test = ProgramTest::new(
        "kamui_example_program",
        game_program_id,
        None,
    );

    // Create MockProver first since we need its program ID and BanksClient
    let mut mock_prover = MockProver::new().await;
    let vrf_program_id = mock_prover.program_id;
    let payer = mock_prover.payer.insecure_clone();
    let recent_blockhash = mock_prover.recent_blockhash;

    // Step 1: Initialize game state
    println!("Initializing game state...");
    
    // Step 1: Create VRF subscription
    println!("Creating VRF subscription...");
    let subscription_owner = Keypair::new();
    let subscription_account = Keypair::new();
    
    // Fund the subscription owner account
    let fund_tx = Transaction::new_signed_with_payer(
        &[system_instruction::transfer(
            &payer.pubkey(),
            &subscription_owner.pubkey(),
            10_000_000, // 10 SOL should be more than enough
        )],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );
    mock_prover.banks_client.process_transaction(fund_tx).await?;
    
    let create_sub_ix = VrfCoordinatorInstruction::CreateSubscription {
        min_balance: 1_000_000,  // 1 SOL minimum balance
        confirmations: 1,
    };
    let create_sub_ix_data = borsh::to_vec(&create_sub_ix)?;
    let create_sub_ix = Instruction {
        program_id: vrf_program_id,
        accounts: vec![
            AccountMeta::new(subscription_owner.pubkey(), true),
            AccountMeta::new(subscription_account.pubkey(), true),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data: create_sub_ix_data,
    };

    let mut transaction = Transaction::new_with_payer(
        &[create_sub_ix],
        Some(&payer.pubkey()),
    );
    transaction.sign(&[&payer, &subscription_owner, &subscription_account], recent_blockhash);
    mock_prover.banks_client.process_transaction(transaction).await?;

    // Verify subscription account was created correctly
    let subscription_data = mock_prover.banks_client.get_account(subscription_account.pubkey()).await?.unwrap();
    println!("Subscription account owner: {:?}", subscription_data.owner);
    println!("Subscription account data length: {}", subscription_data.data.len());
    println!("Subscription account lamports: {}", subscription_data.lamports);
    println!("Subscription account data: {:?}", subscription_data.data);

    // Create token accounts for funding
    let mint = native_mint::id();

    // Create funder's token account
    let funder_token = spl_associated_token_account::get_associated_token_address(
        &subscription_owner.pubkey(),
        &mint,
    );
    let create_funder_token_ix = spl_associated_token_account::instruction::create_associated_token_account(
        &payer.pubkey(),
        &subscription_owner.pubkey(),
        &mint,
        &spl_token::id(),
    );

    // Create subscription's token account
    let subscription_token = spl_associated_token_account::get_associated_token_address(
        &subscription_account.pubkey(),
        &mint,
    );
    let create_sub_token_ix = spl_associated_token_account::instruction::create_associated_token_account(
        &payer.pubkey(),
        &subscription_account.pubkey(),
        &mint,
        &spl_token::id(),
    );

    // Create and initialize token accounts
    let mut transaction = Transaction::new_with_payer(
        &[create_funder_token_ix, create_sub_token_ix],
        Some(&payer.pubkey()),
    );
    transaction.sign(&[&payer], recent_blockhash);
    mock_prover.banks_client.process_transaction(transaction).await?;

    // Wrap SOL into native SOL tokens
    let wrap_sol_ix = spl_token::instruction::sync_native(
        &spl_token::id(),
        &funder_token,
    )?;
    let transfer_sol_ix = system_instruction::transfer(
        &subscription_owner.pubkey(),
        &funder_token,
        5_000_000,  // Amount to wrap
    );

    let mut transaction = Transaction::new_with_payer(
        &[transfer_sol_ix, wrap_sol_ix],
        Some(&payer.pubkey()),
    );
    transaction.sign(&[&payer, &subscription_owner], recent_blockhash);
    mock_prover.banks_client.process_transaction(transaction).await?;

    // Fund the subscription
    let fund_sub_ix = VrfCoordinatorInstruction::FundSubscription {
        amount: 5_000_000,  // Fund with 5 SOL worth of tokens
    };
    let fund_sub_ix_data = borsh::to_vec(&fund_sub_ix)?;
    let fund_sub_ix = Instruction {
        program_id: vrf_program_id,
        accounts: vec![
            AccountMeta::new(subscription_owner.pubkey(), true),
            AccountMeta::new(subscription_account.pubkey(), false),
            AccountMeta::new(funder_token, false),
            AccountMeta::new(subscription_token, false),
            AccountMeta::new_readonly(spl_token::id(), false),
        ],
        data: fund_sub_ix_data,
    };

    let mut transaction = Transaction::new_with_payer(
        &[fund_sub_ix],
        Some(&payer.pubkey()),
    );
    transaction.sign(&[&payer, &subscription_owner], recent_blockhash);
    mock_prover.banks_client.process_transaction(transaction).await?;

    // Step 2: Initialize game
    println!("Initializing game...");
    let game_owner = Keypair::new();
    
    // Fund the game owner account
    let fund_tx = Transaction::new_signed_with_payer(
        &[system_instruction::transfer(
            &payer.pubkey(),
            &game_owner.pubkey(),
            10_000_000, // 10 SOL should be more than enough
        )],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );
    mock_prover.banks_client.process_transaction(fund_tx).await?;
    
    // Derive the game state PDA
    let (game_state_pda, _bump) = Pubkey::find_program_address(
        &[b"game_state", game_owner.pubkey().as_ref()],
        &game_program_id,
    );

    let ix = GameInstruction::Initialize;
    let ix_data = borsh::to_vec(&ix)?;
    let mut transaction = Transaction::new_with_payer(
        &[Instruction {
            program_id: game_program_id,
            accounts: vec![
                AccountMeta::new(game_owner.pubkey(), true),
                AccountMeta::new(game_state_pda, false),
                AccountMeta::new_readonly(subscription_account.pubkey(), false),
                AccountMeta::new_readonly(system_program::id(), false),
            ],
            data: ix_data,
        }],
        Some(&payer.pubkey()),
    );
    transaction.sign(&[&payer, &game_owner], recent_blockhash);
    mock_prover.banks_client.process_transaction(transaction).await?;

    // Verify the account was created correctly
    let game_account = mock_prover.banks_client.get_account(game_state_pda).await?.unwrap();
    println!("Account owner: {:?}", game_account.owner);
    println!("Account data length: {}", game_account.data.len());
    println!("Account lamports: {}", game_account.lamports);

    // Step 3: Request random number
    println!("Requesting random number...");
    
    // Read the subscription account to get the current nonce
    let subscription_data = mock_prover.banks_client.get_account(subscription_account.pubkey()).await?.unwrap();
    let subscription = Subscription::try_from_slice(&subscription_data.data[8..])?;
    let next_nonce = subscription.nonce.checked_add(1).unwrap();
    
    // Derive the request account PDA
    let (request_pda, bump) = Pubkey::find_program_address(
        &[
            b"request",
            &subscription_account.pubkey().to_bytes(),
            &next_nonce.to_le_bytes(),
        ],
        &vrf_program_id,
    );

    // Create request account with RequestRandomness instruction
    let request_ix = VrfCoordinatorInstruction::RequestRandomness {
        seed: [0u8; 32],
        callback_data: borsh::to_vec(&GameInstruction::ConsumeRandomness)?,
        num_words: 1,
        minimum_confirmations: 1,
        callback_gas_limit: 200_000,
    };

    let request_ix_data = borsh::to_vec(&request_ix)?;
    let request_ix = Instruction {
        program_id: vrf_program_id,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(request_pda, false),
            AccountMeta::new_readonly(subscription_account.pubkey(), false),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data: request_ix_data,
    };

    let mut transaction = Transaction::new_with_payer(
        &[request_ix],
        Some(&payer.pubkey()),
    );
    transaction.sign(&[&payer], recent_blockhash);
    mock_prover.banks_client.process_transaction(transaction).await?;

    // Verify game state is pending
    let game_account = mock_prover.banks_client
        .get_account(game_state_pda)
        .await?
        .unwrap();
    
    println!("Account owner after request: {:?}", game_account.owner);
    println!("Account data length: {}", game_account.data.len());
    println!("Account data: {:?}", game_account.data);
    
    let game_state = GameState::try_from_slice(&game_account.data)?;
    println!("Successfully deserialized game state: {:?}", game_state);
    assert!(game_state.is_pending);

    // Step 4: Setup oracle and fulfill randomness
    println!("Setting up oracle and fulfilling randomness...");
    
    // Use MockProver to fulfill the randomness request
    mock_prover.process_randomness_request(
        request_pda,
        game_program_id,
        [0u8; 32],
    ).await?;

    // Step 5: Consume randomness
    println!("Consuming randomness...");
    let consume_ix = GameInstruction::ConsumeRandomness;
    let consume_ix_data = borsh::to_vec(&consume_ix)?;
    let consume_ix = Instruction {
        program_id: game_program_id,
        accounts: vec![
            AccountMeta::new_readonly(mock_prover.get_vrf_result_account(), false),
            AccountMeta::new_readonly(request_pda, false),
            AccountMeta::new(game_state_pda, false),
        ],
        data: consume_ix_data,
    };

    let mut transaction = Transaction::new_with_payer(
        &[consume_ix],
        Some(&payer.pubkey()),
    );
    transaction.sign(&[&payer], recent_blockhash);
    mock_prover.banks_client.process_transaction(transaction).await?;

    // Step 6: Verify final game state
    println!("Verifying final game state...");
    let game_account = mock_prover.banks_client.get_account(game_state_pda).await?.unwrap();
    println!("Account owner after consume: {:?}", game_account.owner);
    println!("Account data length: {}", game_account.data.len());
    println!("Account data: {:?}", game_account.data);
    
    let game_state = GameState::try_from_slice(&game_account.data)?;
    println!("Final game state: {:?}", game_state);
    assert!(!game_state.is_pending, "Game should no longer be pending");
    assert!(game_state.current_number > 0, "Game state should have a new random number");

    Ok(())
} 