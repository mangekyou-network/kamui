use {
    borsh::{BorshSerialize, BorshDeserialize},
    kamui_example_program::{
        instruction::VrfCoordinatorInstruction,
        state::{Subscription, RandomnessRequest, RequestStatus},
        example_consumer::{GameState, GameInstruction},
    },
    solana_program::{
        instruction::{AccountMeta, Instruction},
        pubkey::Pubkey,
        system_program,
    },
    solana_program_test::*,
    solana_sdk::{
        signature::Keypair,
        signer::Signer,
        transaction::Transaction,
        hash::Hash,
    },
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

    let (mut banks_client, payer, recent_blockhash) = program_test.start().await;
    
    (banks_client, payer, recent_blockhash, vrf_program_id, game_program_id)
}

#[tokio::test]
async fn test_full_vrf_flow() -> Result<(), Box<dyn std::error::Error>> {
    let (mut banks_client, payer, recent_blockhash, vrf_program_id, game_program_id) = setup_test().await;

    // Step 1: Create VRF subscription
    println!("Creating VRF subscription...");
    let subscription_owner = Keypair::new();
    let subscription_account = Keypair::new();
    
    let create_sub_ix = VrfCoordinatorInstruction::CreateSubscription {
        min_balance: 1000000,
        confirmations: 1,
    };
    let create_sub_ix_data = borsh::to_vec(&create_sub_ix)?;
    let create_sub_ix = Instruction {
        program_id: vrf_program_id,
        accounts: vec![
            AccountMeta::new(subscription_owner.pubkey(), true),
            AccountMeta::new(subscription_account.pubkey(), false),
            AccountMeta::new(system_program::id(), false),
        ],
        data: create_sub_ix_data,
    };

    let mut transaction = Transaction::new_with_payer(
        &[create_sub_ix],
        Some(&payer.pubkey()),
    );
    transaction.sign(&[&payer, &subscription_owner], recent_blockhash);
    banks_client.process_transaction(transaction).await.unwrap();

    // Step 2: Initialize game
    println!("Initializing game...");
    let game_owner = Keypair::new();
    let game_state = Keypair::new();

    let init_game_ix = GameInstruction::Initialize;
    let init_game_ix_data = borsh::to_vec(&init_game_ix)?;
    let init_game_ix = Instruction {
        program_id: game_program_id,
        accounts: vec![
            AccountMeta::new(game_owner.pubkey(), true),
            AccountMeta::new(game_state.pubkey(), false),
            AccountMeta::new_readonly(subscription_account.pubkey(), false),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data: init_game_ix_data,
    };

    let mut transaction = Transaction::new_with_payer(
        &[init_game_ix],
        Some(&payer.pubkey()),
    );
    transaction.sign(&[&payer, &game_owner], recent_blockhash);
    banks_client.process_transaction(transaction).await.unwrap();

    // Step 3: Request random number
    println!("Requesting random number...");
    let request_account = Keypair::new();

    let request_ix = GameInstruction::RequestNewNumber;
    let request_ix_data = borsh::to_vec(&request_ix)?;
    let request_ix = Instruction {
        program_id: game_program_id,
        accounts: vec![
            AccountMeta::new(game_owner.pubkey(), true),
            AccountMeta::new(game_state.pubkey(), false),
            AccountMeta::new(request_account.pubkey(), false),
            AccountMeta::new_readonly(subscription_account.pubkey(), false),
            AccountMeta::new_readonly(vrf_program_id, false),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data: request_ix_data,
    };

    let mut transaction = Transaction::new_with_payer(
        &[request_ix],
        Some(&payer.pubkey()),
    );
    transaction.sign(&[&payer, &game_owner], recent_blockhash);
    banks_client.process_transaction(transaction).await.unwrap();

    // Verify game state is pending
    let game_account = banks_client
        .get_account(game_state.pubkey())
        .await
        .unwrap()
        .unwrap();
    let game_state_data = GameState::try_from_slice(&game_account.data).unwrap();
    assert!(game_state_data.is_pending, "Game should be in pending state");

    // Step 4: Simulate VRF proof fulfillment
    println!("Simulating VRF proof fulfillment...");
    let vrf_result = Keypair::new();
    let oracle = Keypair::new();

    // Create mock proof and public key
    let proof = vec![1, 2, 3, 4];  // Mock proof
    let public_key = vec![5, 6, 7, 8];  // Mock public key

    let fulfill_ix = VrfCoordinatorInstruction::FulfillRandomness {
        proof,
        public_key,
    };
    let fulfill_ix_data = borsh::to_vec(&fulfill_ix)?;
    let fulfill_ix = Instruction {
        program_id: vrf_program_id,
        accounts: vec![
            AccountMeta::new(oracle.pubkey(), true),
            AccountMeta::new(request_account.pubkey(), false),
            AccountMeta::new(vrf_result.pubkey(), false),
            AccountMeta::new_readonly(game_program_id, false),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data: fulfill_ix_data,
    };

    let mut transaction = Transaction::new_with_payer(
        &[fulfill_ix],
        Some(&payer.pubkey()),
    );
    transaction.sign(&[&payer, &oracle], recent_blockhash);
    banks_client.process_transaction(transaction).await.unwrap();

    // Verify final game state
    let game_account = banks_client
        .get_account(game_state.pubkey())
        .await
        .unwrap()
        .unwrap();
    let final_game_state = GameState::try_from_slice(&game_account.data).unwrap();
    assert!(!final_game_state.is_pending, "Game should no longer be pending");
    assert!(final_game_state.current_number > 0, "Game should have a random number");

    println!("Test completed successfully!");
    println!("Final random number: {}", final_game_state.current_number);
    Ok(())
} 