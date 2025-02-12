use {
    borsh::{BorshDeserialize},
    kamui_example_program::{
        instruction::VrfCoordinatorInstruction,
        state::{Subscription, VrfResult},
        example_consumer::{GameInstruction, GameState},
    },
    solana_program::{
        instruction::{AccountMeta, Instruction},
        pubkey::Pubkey,
        system_program,
        system_instruction,
    },
    solana_client::rpc_client::RpcClient,
    solana_sdk::{
        commitment_config::CommitmentConfig,
        signature::{Keypair, Signer},
        transaction::Transaction,
    },
    spl_token::native_mint,
    spl_associated_token_account,
    mangekyou::kamui_vrf::{
        ecvrf::ECVRFKeyPair,
        VRFKeyPair,
    },
    rand::thread_rng,
    anyhow::Result,
    std::{str::FromStr, fs::File, io::Read},
};

#[tokio::test]
async fn test_vrf_flow_devnet() -> Result<()> {
    // Connect to devnet
    let rpc_url = "https://api.devnet.solana.com".to_string();
    let rpc_client = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());

    // Load the deployed program IDs
    let vrf_program_id = Pubkey::from_str("1111111QLbz7JHiBTspS962RLKV8GndWFwiEaqKM").unwrap();
    let game_program_id = Pubkey::from_str("1111111ogCyDbaRMvkdsHB3qfdyFYaG1WtRUAfdh").unwrap();

    // Load keypair from file
    let mut keypair_file = File::open("keypair.json").expect("Failed to open keypair.json");
    let mut keypair_data = String::new();
    keypair_file.read_to_string(&mut keypair_data).expect("Failed to read keypair.json");
    let keypair_bytes: Vec<u8> = serde_json::from_str(&keypair_data).expect("Failed to parse keypair JSON");
    let payer = Keypair::from_bytes(&keypair_bytes).expect("Failed to create keypair from bytes");
    
    println!("Using keypair with pubkey: {}", payer.pubkey());
    
    // Verify the balance
    let balance = rpc_client.get_balance(&payer.pubkey()).expect("Failed to get balance");
    println!("Current balance: {} SOL", balance as f64 / 1_000_000_000.0);

    if balance == 0 {
        panic!("Account has no SOL balance");
    }

    // Step 1: Create VRF subscription
    println!("Creating VRF subscription...");
    let subscription_owner = Keypair::new();
    let subscription_account = Keypair::new();
    
    // Fund the subscription owner account
    let recent_blockhash = rpc_client.get_latest_blockhash().expect("Failed to get recent blockhash");
    let fund_tx = Transaction::new_signed_with_payer(
        &[system_instruction::transfer(
            &payer.pubkey(),
            &subscription_owner.pubkey(),
            10_000_000_000, // 10 SOL
        )],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );
    rpc_client.send_and_confirm_transaction_with_spinner(&fund_tx)
        .expect("Failed to fund subscription owner");

    // Create subscription
    let create_sub_ix = VrfCoordinatorInstruction::CreateSubscription {
        min_balance: 1_000_000_000,  // 1 SOL minimum balance
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

    let recent_blockhash = rpc_client.get_latest_blockhash().expect("Failed to get recent blockhash");
    let mut transaction = Transaction::new_with_payer(
        &[create_sub_ix],
        Some(&payer.pubkey()),
    );
    transaction.sign(&[&payer, &subscription_owner, &subscription_account], recent_blockhash);
    
    println!("Sending transaction to create subscription...");
    let signature = rpc_client
        .send_and_confirm_transaction_with_spinner(&transaction)
        .expect("Failed to create subscription");
    println!("Subscription created! Signature: {}", signature);

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

    // Create token accounts
    let recent_blockhash = rpc_client.get_latest_blockhash().expect("Failed to get recent blockhash");
    let mut transaction = Transaction::new_with_payer(
        &[create_funder_token_ix, create_sub_token_ix],
        Some(&payer.pubkey()),
    );
    transaction.sign(&[&payer], recent_blockhash);
    
    println!("Creating token accounts...");
    let signature = rpc_client
        .send_and_confirm_transaction_with_spinner(&transaction)
        .expect("Failed to create token accounts");
    println!("Token accounts created! Signature: {}", signature);

    // Fund subscription
    let wrap_sol_ix = spl_token::instruction::sync_native(
        &spl_token::id(),
        &funder_token,
    )?;
    let transfer_sol_ix = system_instruction::transfer(
        &subscription_owner.pubkey(),
        &funder_token,
        5_000_000_000,  // 5 SOL
    );

    let recent_blockhash = rpc_client.get_latest_blockhash().expect("Failed to get recent blockhash");
    let mut transaction = Transaction::new_with_payer(
        &[transfer_sol_ix, wrap_sol_ix],
        Some(&payer.pubkey()),
    );
    transaction.sign(&[&payer, &subscription_owner], recent_blockhash);
    
    println!("Funding subscription...");
    let signature = rpc_client
        .send_and_confirm_transaction_with_spinner(&transaction)
        .expect("Failed to fund subscription");
    println!("Subscription funded! Signature: {}", signature);

    // Step 2: Initialize game
    println!("Initializing game...");
    let game_owner = Keypair::new();
    
    // Fund the game owner account
    let recent_blockhash = rpc_client.get_latest_blockhash().expect("Failed to get recent blockhash");
    let fund_tx = Transaction::new_signed_with_payer(
        &[system_instruction::transfer(
            &payer.pubkey(),
            &game_owner.pubkey(),
            10_000_000_000, // 10 SOL
        )],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );
    rpc_client.send_and_confirm_transaction_with_spinner(&fund_tx)
        .expect("Failed to fund game owner");
    
    // Derive the game state PDA
    let (game_state_pda, _bump) = Pubkey::find_program_address(
        &[b"game_state", game_owner.pubkey().as_ref()],
        &game_program_id,
    );

    let ix = GameInstruction::Initialize;
    let ix_data = borsh::to_vec(&ix)?;
    let recent_blockhash = rpc_client.get_latest_blockhash().expect("Failed to get recent blockhash");
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
    
    println!("Initializing game state...");
    let signature = rpc_client
        .send_and_confirm_transaction_with_spinner(&transaction)
        .expect("Failed to initialize game");
    println!("Game initialized! Signature: {}", signature);

    // Step 3: Request random number
    println!("Requesting random number...");
    
    // Read subscription account to get current nonce
    let subscription_data = rpc_client.get_account_data(&subscription_account.pubkey())?;
    let subscription = Subscription::try_from_slice(&subscription_data[8..])?;
    let next_nonce = subscription.nonce.checked_add(1).unwrap();

    // Derive request account PDA
    let (request_account, _bump) = Pubkey::find_program_address(
        &[
            b"request",
            subscription_account.pubkey().as_ref(),
            &next_nonce.to_le_bytes(),
        ],
        &vrf_program_id
    );

    // Request random number
    let ix = GameInstruction::RequestNewNumber;
    let ix_data = borsh::to_vec(&ix)?;
    let recent_blockhash = rpc_client.get_latest_blockhash().expect("Failed to get recent blockhash");
    let mut transaction = Transaction::new_with_payer(
        &[Instruction {
            program_id: game_program_id,
            accounts: vec![
                AccountMeta::new(game_owner.pubkey(), true),
                AccountMeta::new(game_state_pda, false),
                AccountMeta::new(request_account, false),
                AccountMeta::new_readonly(subscription_account.pubkey(), false),
                AccountMeta::new_readonly(vrf_program_id, false),
                AccountMeta::new_readonly(system_program::id(), false),
            ],
            data: ix_data,
        }],
        Some(&payer.pubkey()),
    );
    transaction.sign(&[&payer, &game_owner], recent_blockhash);
    
    println!("Requesting random number...");
    let signature = rpc_client
        .send_and_confirm_transaction_with_spinner(&transaction)
        .expect("Failed to request random number");
    println!("Random number requested! Signature: {}", signature);

    // Step 4: Fulfill randomness
    println!("Fulfilling randomness...");

    // Generate VRF proof
    let vrf_keypair = ECVRFKeyPair::generate(&mut thread_rng());
    let seed = [0u8; 32];  // Example seed
    let (output, proof) = vrf_keypair.output(&seed);
    let proof_bytes = proof.to_bytes();
    let public_key_bytes = vrf_keypair.pk.as_ref().to_vec();

    // Create VRF result PDA
    let (vrf_result, _bump) = Pubkey::find_program_address(
        &[b"vrf_result", request_account.as_ref()],
        &vrf_program_id
    );

    // Call FulfillRandomness on VRF coordinator
    let fulfill_ix = VrfCoordinatorInstruction::FulfillRandomness {
        proof: proof_bytes.to_vec(),
        public_key: public_key_bytes,
    };
    let fulfill_ix_data = borsh::to_vec(&fulfill_ix)?;

    let recent_blockhash = rpc_client.get_latest_blockhash().expect("Failed to get recent blockhash");
    let mut transaction = Transaction::new_with_payer(
        &[Instruction {
            program_id: vrf_program_id,
            accounts: vec![
                AccountMeta::new(payer.pubkey(), true),  // oracle
                AccountMeta::new(request_account, false),  // request_account
                AccountMeta::new(vrf_result, false),  // vrf_result_account
                AccountMeta::new_readonly(game_program_id, false),  // callback_program
                AccountMeta::new_readonly(subscription_account.pubkey(), false),  // subscription_account
                AccountMeta::new_readonly(system_program::id(), false),  // system_program
                AccountMeta::new_readonly(game_program_id, false),  // game_program
                AccountMeta::new(game_state_pda, false),  // game_state
            ],
            data: fulfill_ix_data,
        }],
        Some(&payer.pubkey()),
    );
    transaction.sign(&[&payer], recent_blockhash);
    
    println!("Fulfilling randomness...");
    let signature = rpc_client
        .send_and_confirm_transaction_with_spinner(&transaction)
        .expect("Failed to fulfill randomness");
    println!("Randomness fulfilled! Signature: {}", signature);

    // Then call ConsumeRandomness on our game program
    let consume_ix = GameInstruction::ConsumeRandomness;
    let consume_ix_data = borsh::to_vec(&consume_ix)?;
    let recent_blockhash = rpc_client.get_latest_blockhash().expect("Failed to get recent blockhash");
    let mut transaction = Transaction::new_with_payer(
        &[Instruction {
            program_id: game_program_id,
            accounts: vec![
                AccountMeta::new_readonly(vrf_result, false),  // vrf_result
                AccountMeta::new_readonly(request_account, false),  // request_account
                AccountMeta::new(game_state_pda, false),  // game_state
            ],
            data: consume_ix_data,
        }],
        Some(&payer.pubkey()),
    );
    transaction.sign(&[&payer], recent_blockhash);
    
    println!("Consuming randomness...");
    let signature = rpc_client
        .send_and_confirm_transaction_with_spinner(&transaction)
        .expect("Failed to consume randomness");
    println!("Randomness consumed! Signature: {}", signature);

    // Verify final game state
    let game_account_data = rpc_client.get_account_data(&game_state_pda)?;
    let final_state = GameState::try_from_slice(&game_account_data[8..])?;
    assert!(!final_state.is_pending);
    assert!(final_state.current_number > 0 && final_state.current_number <= 100);

    println!("VRF flow test completed successfully on devnet!");
    println!("Final game state: {:?}", final_state);
    Ok(())
} 