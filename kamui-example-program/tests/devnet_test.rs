use {
    borsh::BorshSerialize,
    solana_client::rpc_client::RpcClient,
    solana_program::{
        instruction::{AccountMeta, Instruction},
        message::Message,
        pubkey::Pubkey,
    },
    solana_sdk::{
        commitment_config::CommitmentConfig,
        signature::{Keypair, Signer},
        transaction::Transaction,
    },
    std::{str::FromStr, fs::File, io::Read},
    mangekyou::{
        kamui_vrf::{
            ecvrf::ECVRFKeyPair,
            VRFKeyPair,
            VRFProof,
            VRFPublicKey,
        },
        serde_helpers::ToFromByteArray,
    },
    rand::thread_rng,
    hex,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_vrf_verification_devnet() {
    // Connect to devnet
    let rpc_url = "https://api.devnet.solana.com".to_string();
    let rpc_client = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());

    // Use the deployed program ID
    let program_id = Pubkey::from_str("4qqRVYJAeBynm2yTydBkTJ9wVay3CrUfZ7gf9chtWS5Y").unwrap();

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

    // Generate a new VRF keypair
    let vrf_keypair = ECVRFKeyPair::generate(&mut thread_rng());
    let alpha_string = b"Hello, world!";
    
    // Generate VRF proof and output
    let (output, proof) = vrf_keypair.output(alpha_string);
    println!("Generated VRF output: {:?}", hex::encode(&output));
    
    // Get public key bytes
    let public_key_bytes = vrf_keypair.pk.as_ref().to_vec();
    
    // Get proof bytes in the format expected by our program (gamma || s || c)
    let proof_bytes = proof.to_bytes();
    let formatted_proof = proof_bytes.clone();

    println!("Gamma: {:?}", hex::encode(&proof_bytes[0..32]));
    println!("s: {:?}", hex::encode(&proof_bytes[32..64]));
    println!("c: {:?}", hex::encode(&proof_bytes[64..80]));
    println!("Proof bytes: {:?}", hex::encode(&proof_bytes));
    println!("Formatted proof: {:?}", hex::encode(&formatted_proof));
    println!("Public key: {:?}", hex::encode(&public_key_bytes));
    println!("Alpha string: {:?}", hex::encode(alpha_string));

    // Create the instruction data
    let verify_input = kamui_example_program::VerifyVrfInput {
        alpha_string: alpha_string.to_vec(),
        proof_bytes: formatted_proof,
        public_key_bytes,
    };

    let instruction = Instruction::new_with_borsh(
        program_id,
        &verify_input,
        vec![AccountMeta::new(payer.pubkey(), true)],
    );

    // Get recent blockhash
    let recent_blockhash = rpc_client
        .get_latest_blockhash()
        .expect("Failed to get recent blockhash");

    // Create and sign transaction
    let message = Message::new_with_blockhash(
        &[instruction],
        Some(&payer.pubkey()),
        &recent_blockhash,
    );
    let mut transaction = Transaction::new_unsigned(message);
    transaction.sign(&[&payer], recent_blockhash);

    println!("Sending transaction to verify VRF proof...");
    
    // Send and confirm transaction
    let signature = rpc_client
        .send_and_confirm_transaction_with_spinner(&transaction)
        .expect("Failed to send and confirm transaction");

    println!("Transaction successful!");
    println!("Signature: {}", signature);
    println!("View transaction: https://explorer.solana.com/tx/{}?cluster=devnet", signature);
} 