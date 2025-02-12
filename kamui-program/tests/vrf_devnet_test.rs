use {
    borsh::{BorshDeserialize, BorshSerialize},
    kamui_program::{
        instruction::VrfCoordinatorInstruction,
        state::Subscription,
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
        sysvar::rent::Rent,
    },
    spl_token::native_mint,
    spl_associated_token_account,
    mangekyou::kamui_vrf::{
        ecvrf::{ECVRFKeyPair, ECVRFProof},
        VRFProof,
        VRFKeyPair,
    },
    rand::thread_rng,
    anyhow::Result,
    std::{str::FromStr, fs::File, io::Read},
    serde_json,
};

// Game-related structures for testing
#[derive(BorshSerialize, BorshDeserialize)]
pub enum GameInstruction {
    Initialize,
    RequestNewNumber,
    ConsumeRandomness,
}

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

impl GameState {
    pub fn try_deserialize(data: &[u8]) -> Result<Self> {
        // Check discriminator
        if data.len() < 8 || &data[0..8] != b"GAMESTAT" {
            return Err(anyhow::anyhow!("Invalid discriminator"));
        }
        // Skip discriminator and deserialize the rest
        Ok(Self::try_from_slice(&data[8..])?)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_vrf_flow_devnet() -> Result<()> {
    // Connect to devnet
    let rpc_url = "https://api.devnet.solana.com".to_string();
    let rpc_client = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());

    // Load program IDs
    let vrf_program_id = Pubkey::from_str("BfwfooykCSdb1vgu6FcP75ncUgdcdt4ciUaeaSLzxM4D").unwrap();
    let game_program_id = Pubkey::from_str("5gSZAw9aDQYGJABr6guQqPRFzyX656BSoiEdhHaUzyh6").unwrap();
    

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
            5_000_000, // 0.005 SOL
        )],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );
    rpc_client.send_and_confirm_transaction_with_spinner(&fund_tx)
        .expect("Failed to fund subscription owner");

    // Create subscription
    let create_sub_ix = VrfCoordinatorInstruction::CreateSubscription {
        min_balance: 500_000,  // Reduced from 1_000_000 to 0.0005 SOL
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
    // First wrap SOL into the funder's token account
    let wrap_amount = 1_000_000; // Reduced from 2_000_000 to 0.001 SOL
    let transfer_ix = system_instruction::transfer(
        &subscription_owner.pubkey(),
        &funder_token,
        wrap_amount,
    );
    let sync_native_ix = spl_token::instruction::sync_native(
        &spl_token::id(),
        &funder_token,
    )?;

    let recent_blockhash = rpc_client.get_latest_blockhash().expect("Failed to get recent blockhash");
    let mut transaction = Transaction::new_with_payer(
        &[transfer_ix, sync_native_ix],
        Some(&payer.pubkey()),
    );
    transaction.sign(&[&payer, &subscription_owner], recent_blockhash);
    
    println!("Wrapping SOL...");
    let signature = rpc_client
        .send_and_confirm_transaction_with_spinner(&transaction)
        .expect("Failed to wrap SOL");
    println!("SOL wrapped! Signature: {}", signature);

    // Now fund the subscription
    let fund_sub_ix = VrfCoordinatorInstruction::FundSubscription {
        amount: wrap_amount,
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

    let recent_blockhash = rpc_client.get_latest_blockhash().expect("Failed to get recent blockhash");
    let mut transaction = Transaction::new_with_payer(
        &[fund_sub_ix],
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
            10_000_000, // 0.01 SOL
        )],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );
    rpc_client.send_and_confirm_transaction_with_spinner(&fund_tx)
        .expect("Failed to fund game owner");
    
    // Derive the game state PDA
    let (game_state_pda, bump) = Pubkey::find_program_address(
        &[b"game_state", game_owner.pubkey().as_ref()],
        &game_program_id,
    );

    // Initialize game instruction
    let init_ix = GameInstruction::Initialize;
    let init_ix_data = borsh::to_vec(&init_ix)?;
    let init_game_ix = Instruction {
        program_id: game_program_id,
        accounts: vec![
            AccountMeta::new(game_owner.pubkey(), true),
            AccountMeta::new(game_state_pda, false),
            AccountMeta::new_readonly(subscription_account.pubkey(), false),
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data: init_ix_data,
    };

    let recent_blockhash = rpc_client.get_latest_blockhash().expect("Failed to get recent blockhash");
    let mut transaction = Transaction::new_with_payer(
        &[init_game_ix],
        Some(&payer.pubkey()),
    );
    transaction.sign(&[&payer, &game_owner], recent_blockhash);
    
    println!("Initializing game state...");
    let signature = rpc_client
        .send_and_confirm_transaction_with_spinner(&transaction)
        .expect("Failed to initialize game");
    println!("Game initialized! Signature: {}", signature);

    // Track balances before VRF operations
    let initial_payer_balance = rpc_client.get_balance(&payer.pubkey())?;
    let initial_game_owner_balance = rpc_client.get_balance(&game_owner.pubkey())?;
    println!("\n=== Starting VRF Cost Analysis ===");
    println!("Initial payer balance: {} SOL", initial_payer_balance as f64 / 1_000_000_000.0);
    println!("Initial game owner balance: {} SOL", initial_game_owner_balance as f64 / 1_000_000_000.0);

    // Step 3: Request random number
    println!("\n1. Requesting random number...");
    let pre_request_payer_balance = rpc_client.get_balance(&payer.pubkey())?;
    let pre_request_game_owner_balance = rpc_client.get_balance(&game_owner.pubkey())?;
    
    // Read subscription account to get current nonce
    let subscription_data = rpc_client.get_account_data(&subscription_account.pubkey())?;
    let subscription = Subscription::try_from_slice(&subscription_data[8..])?;
    let next_nonce = subscription.nonce.checked_add(1).unwrap();

    // Derive request account PDA
    let (request_account, _request_bump) = Pubkey::find_program_address(
        &[
            b"request",
            subscription_account.pubkey().as_ref(),
            &next_nonce.to_le_bytes(),
        ],
        &vrf_program_id
    );

    // Create VRF request instruction
    let seed = [0u8; 32];
    let request_ix = VrfCoordinatorInstruction::RequestRandomness {
        seed,
        callback_data: borsh::to_vec(&GameInstruction::ConsumeRandomness)?,
        num_words: 1,
        minimum_confirmations: 1,
        callback_gas_limit: 100_000,  // Reduced from 200_000
    };
    let request_ix_data = borsh::to_vec(&request_ix)?;
    let request_vrf_ix = Instruction {
        program_id: vrf_program_id,
        accounts: vec![
            AccountMeta::new(game_owner.pubkey(), true),  // Game owner is the requester
            AccountMeta::new(request_account, false),  // Request account PDA
            AccountMeta::new(subscription_account.pubkey(), false),  // Subscription account
            AccountMeta::new_readonly(system_program::id(), false),  // System program
        ],
        data: request_ix_data,
    };

    let mut transaction = Transaction::new_with_payer(
        &[request_vrf_ix],
        Some(&payer.pubkey()),
    );
    let recent_blockhash = rpc_client.get_latest_blockhash().expect("Failed to get recent blockhash");
    transaction.sign(
        &[
            &payer,
            &game_owner,  // Game owner must sign as requester
        ],
        recent_blockhash,
    );
    
    println!("Requesting random number...");
    let signature = rpc_client
        .send_and_confirm_transaction_with_spinner(&transaction)
        .expect("Failed to request random number");
    println!("Random number requested! Signature: {}", signature);

    let post_request_payer_balance = rpc_client.get_balance(&payer.pubkey())?;
    let post_request_game_owner_balance = rpc_client.get_balance(&game_owner.pubkey())?;
    let request_cost = (pre_request_payer_balance - post_request_payer_balance) + 
                      (pre_request_game_owner_balance - post_request_game_owner_balance);
    println!("Request cost: {} SOL", request_cost as f64 / 1_000_000_000.0);

    // Step 4: Fulfill randomness
    println!("\n2. Fulfilling randomness...");
    let pre_fulfill_payer_balance = rpc_client.get_balance(&payer.pubkey())?;

    // Generate VRF proof
    let vrf_keypair = ECVRFKeyPair::generate(&mut thread_rng());
    let seed = [0u8; 32];  // Example seed
    let (_output, proof) = vrf_keypair.output(&seed);
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
                AccountMeta::new(request_account, false),  // request_account is writable but not a signer
                AccountMeta::new(vrf_result, false),  // vrf_result_account is writable but not a signer
                AccountMeta::new_readonly(game_program_id, false),  // callback_program
                AccountMeta::new(subscription_account.pubkey(), false),  // subscription_account is writable but not a signer
                AccountMeta::new_readonly(system_program::id(), false),  // system_program
                AccountMeta::new_readonly(game_program_id, false),  // game_program
                AccountMeta::new(game_state_pda, false),  // game_state is writable but not a signer
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

    let post_fulfill_payer_balance = rpc_client.get_balance(&payer.pubkey())?;
    let fulfill_cost = pre_fulfill_payer_balance - post_fulfill_payer_balance;
    println!("Fulfill cost: {} SOL", fulfill_cost as f64 / 1_000_000_000.0);

    // Then call ConsumeRandomness on our game program
    println!("\n3. Consuming randomness...");
    let pre_consume_payer_balance = rpc_client.get_balance(&payer.pubkey())?;
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

    let post_consume_payer_balance = rpc_client.get_balance(&payer.pubkey())?;
    let consume_cost = pre_consume_payer_balance - post_consume_payer_balance;
    println!("Consume cost: {} SOL", consume_cost as f64 / 1_000_000_000.0);

    // Calculate total VRF operation costs
    let total_vrf_cost = request_cost + fulfill_cost + consume_cost;
    println!("\n=== VRF Cost Summary ===");
    println!("Request cost:  {} SOL", request_cost as f64 / 1_000_000_000.0);
    println!("Fulfill cost:  {} SOL", fulfill_cost as f64 / 1_000_000_000.0);
    println!("Consume cost:  {} SOL", consume_cost as f64 / 1_000_000_000.0);
    println!("Total VRF cost: {} SOL", total_vrf_cost as f64 / 1_000_000_000.0);
    println!("==================\n");

    // Verify final game state
    let game_account_data = rpc_client.get_account_data(&game_state_pda)?;
    let final_state = GameState::try_deserialize(&game_account_data)?;
    assert!(!final_state.is_pending);
    assert!(final_state.current_number > 0 && final_state.current_number <= 100);

    println!("VRF flow test completed successfully on devnet!");
    println!("Final game state: {:?}", final_state);

    // Demonstrate subsequent VRF request cost
    println!("\n=== Testing Subsequent VRF Request Cost ===");
    let pre_second_request_balance = rpc_client.get_balance(&payer.pubkey())?;
    
    // Read updated subscription nonce
    let subscription_data = rpc_client.get_account_data(&subscription_account.pubkey())?;
    let subscription = Subscription::try_from_slice(&subscription_data[8..])?;
    let next_nonce = subscription.nonce.checked_add(1).unwrap();

    // Derive new request account PDA
    let (new_request_account, _) = Pubkey::find_program_address(
        &[
            b"request",
            subscription_account.pubkey().as_ref(),
            &next_nonce.to_le_bytes(),
        ],
        &vrf_program_id
    );

    // Create second VRF request
    let request_ix = VrfCoordinatorInstruction::RequestRandomness {
        seed: [1u8; 32],  // Different seed
        callback_data: borsh::to_vec(&GameInstruction::ConsumeRandomness)?,
        num_words: 1,
        minimum_confirmations: 1,
        callback_gas_limit: 100_000,
    };
    let request_ix_data = borsh::to_vec(&request_ix)?;
    let request_vrf_ix = Instruction {
        program_id: vrf_program_id,
        accounts: vec![
            AccountMeta::new(game_owner.pubkey(), true),
            AccountMeta::new(new_request_account, false),
            AccountMeta::new(subscription_account.pubkey(), false),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data: request_ix_data,
    };

    let mut transaction = Transaction::new_with_payer(
        &[request_vrf_ix],
        Some(&payer.pubkey()),
    );
    let recent_blockhash = rpc_client.get_latest_blockhash()?;
    transaction.sign(&[&payer, &game_owner], recent_blockhash);
    
    println!("Making second VRF request...");
    let signature = rpc_client
        .send_and_confirm_transaction_with_spinner(&transaction)
        .expect("Failed to make second request");
    println!("Second request made! Signature: {}", signature);

    let post_second_request_balance = rpc_client.get_balance(&payer.pubkey())?;
    let second_request_cost = pre_second_request_balance - post_second_request_balance;
    
    println!("\n=== Cost Comparison ===");
    println!("First request total cost:  {} SOL", total_vrf_cost as f64 / 1_000_000_000.0);
    println!("Second request cost:       {} SOL", second_request_cost as f64 / 1_000_000_000.0);
    println!("Cost reduction:            {:.2}%", 
        ((total_vrf_cost - second_request_cost) as f64 / total_vrf_cost as f64) * 100.0);
    println!("==================\n");

    Ok(())
} 