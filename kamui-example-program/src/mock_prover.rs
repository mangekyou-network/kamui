use {
    crate::{
        instruction::VrfCoordinatorInstruction,
        event::VrfEvent,
        state::{OracleConfig, RandomnessRequest, RequestStatus, VrfResult},
    },
    borsh::{BorshDeserialize, BorshSerialize},
    mangekyou::kamui_vrf::{
        ecvrf::{ECVRFKeyPair, ECVRFProof},
        VRFProof,
        VRFKeyPair
    },
    solana_program::{
        instruction::{AccountMeta, Instruction},
        pubkey::Pubkey,
        system_program,
        system_instruction,
        rent::Rent,
    },
    solana_program_test::BanksClient,
    solana_program_test::ProgramTest,
    solana_sdk::{
        signature::Keypair,
        signer::Signer,
        transaction::Transaction,
        hash::Hash,
    },
    base64::Engine,
};

pub struct MockProver {
    pub keypair: ECVRFKeyPair,
    pub program_id: Pubkey,
    pub banks_client: BanksClient,
    pub payer: Keypair,
    pub recent_blockhash: Hash,
    vrf_result: Option<Pubkey>,
}

impl MockProver {
    pub async fn new() -> Self {
        let program_id = Pubkey::new_unique();
        let program_test = ProgramTest::new(
            "kamui_example_program",
            program_id,
            None,
        );

        let (banks_client, payer, recent_blockhash) = program_test.start().await;
        let keypair = ECVRFKeyPair::from_bytes(&[0u8; 32]).unwrap();

        Self {
            keypair,
            program_id,
            banks_client,
            payer,
            recent_blockhash,
            vrf_result: None,
        }
    }

    pub fn parse_vrf_event(log_msg: &str) -> Option<VrfEvent> {
        if !log_msg.starts_with("VRF_EVENT:") {
            return None;
        }

        let base64_data = log_msg.trim_start_matches("VRF_EVENT:").trim();
        let event_data = base64::engine::general_purpose::STANDARD.decode(base64_data).ok()?;
        VrfEvent::try_from_slice(&event_data).ok()
    }

    pub async fn process_randomness_request(
        &mut self,
        request_id: Pubkey,
        requester: Pubkey,
        seed: [u8; 32],
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Generate VRF proof
        let proof = self.keypair.prove(&seed);
        let proof_bytes = <ECVRFProof as VRFProof<64>>::to_bytes(&proof);
        let public_key = self.keypair.pk.as_ref().to_vec();

        // Create VRF result account
        let vrf_result = Keypair::new();
        self.vrf_result = Some(vrf_result.pubkey());

        // Get the request account data
        let request_account = self.banks_client.get_account(request_id).await?.unwrap();
        let request = RandomnessRequest::try_from_slice(&request_account.data)?;

        // Create fulfill randomness instruction
        let fulfill_ix = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new(self.payer.pubkey(), true),
                AccountMeta::new(request_id, false),
                AccountMeta::new(vrf_result.pubkey(), true),
                AccountMeta::new_readonly(requester, false),
                AccountMeta::new_readonly(request.subscription, false),
                AccountMeta::new_readonly(system_program::id(), false),
            ],
            data: borsh::to_vec(&VrfCoordinatorInstruction::FulfillRandomness {
                proof: proof_bytes,
                public_key,
            })?,
        };

        // Send transaction
        let mut transaction = Transaction::new_with_payer(
            &[fulfill_ix],
            Some(&self.payer.pubkey()),
        );
        transaction.sign(&[&self.payer, &vrf_result], self.recent_blockhash);
        self.banks_client.process_transaction(transaction).await?;

        Ok(())
    }

    pub fn get_vrf_result_account(&self) -> Pubkey {
        self.vrf_result.expect("No VRF result account available - call process_randomness_request first")
    }
} 