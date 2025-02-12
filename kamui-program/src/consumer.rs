use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::AccountInfo,
    entrypoint::ProgramResult,
    program_error::ProgramError,
    pubkey::Pubkey,
};

/// Trait that must be implemented by programs that want to consume VRF randomness
pub trait VRFConsumer {
    /// Called by the VRF Coordinator when randomness is fulfilled
    fn consume_randomness(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        randomness: [u8; 64],
    ) -> ProgramResult;
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct VRFRequestParams {
    /// The subscription ID to use for this request
    pub subscription: Pubkey,
    /// Optional seed to mix in with the blockhash for randomness
    pub seed: Option<[u8; 32]>,
    /// Minimum number of confirmations before oracle response
    pub min_confirmations: u8,
    /// Maximum gas to use for the callback
    pub callback_gas_limit: u64,
    /// Arguments to pass to the callback
    pub callback_args: Vec<u8>,
}

/// Helper functions for VRF consumers
pub mod helpers {
    use super::*;
    use solana_program::{
        instruction::{AccountMeta, Instruction},
        system_program,
    };

    pub fn create_vrf_request_instruction(
        program_id: &Pubkey,
        vrf_coordinator: &Pubkey,
        params: VRFRequestParams,
        accounts: Vec<AccountMeta>,
    ) -> Result<Instruction, ProgramError> {
        let mut data = params.try_to_vec()?;
        
        Ok(Instruction {
            program_id: *vrf_coordinator,
            accounts: vec![
                AccountMeta::new(*program_id, true),
                AccountMeta::new_readonly(params.subscription, false),
                AccountMeta::new_readonly(system_program::id(), false),
            ],
            data,
        })
    }

    pub fn parse_vrf_callback(
        instruction_data: &[u8],
    ) -> Result<([u8; 64], Vec<u8>), ProgramError> {
        if instruction_data.len() < 64 {
            return Err(ProgramError::InvalidInstructionData);
        }

        let mut randomness = [0u8; 64];
        randomness.copy_from_slice(&instruction_data[..64]);
        let callback_args = instruction_data[64..].to_vec();

        Ok((randomness, callback_args))
    }
}

/// Example implementation of a VRF consumer
#[cfg(test)]
mod example {
    use super::*;

    pub struct ExampleVRFConsumer;

    impl VRFConsumer for ExampleVRFConsumer {
        fn consume_randomness(
            program_id: &Pubkey,
            accounts: &[AccountInfo],
            randomness: [u8; 64],
        ) -> ProgramResult {
            // Example implementation:
            // 1. Parse the randomness and any additional callback arguments
            // 2. Update game state or other program state based on the randomness
            // 3. Emit an event with the result
            
            msg!("Received randomness: {:?}", randomness);
            
            // Convert randomness to a number between 1 and 100
            let random_number = (randomness[0] as u64 % 100) + 1;
            msg!("Random number between 1-100: {}", random_number);
            
            Ok(())
        }
    }
} 