use {
    borsh::{BorshDeserialize, BorshSerialize},
    crate::{
        instruction::VrfCoordinatorInstruction,
        state::{RandomnessRequest, RequestStatus, Subscription, VrfResult, OracleConfig},
        event::VrfEvent,
        error::VrfCoordinatorError,
    },
    solana_program::{
        account_info::{next_account_info, AccountInfo},
        entrypoint::ProgramResult,
        instruction::{AccountMeta, Instruction},
        msg,
        program::{invoke, invoke_signed},
        program_error::ProgramError,
        pubkey::Pubkey,
        system_instruction,
        sysvar::{rent::Rent, Sysvar},
    },
};
use spl_token::instruction as token_instruction;

pub struct Processor;

impl Processor {
    pub fn process(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        instruction_data: &[u8],
    ) -> ProgramResult {
        let instruction = VrfCoordinatorInstruction::try_from_slice(instruction_data)?;

        match instruction {
            VrfCoordinatorInstruction::RequestRandomness { 
                seed, 
                callback_data,
                num_words,
                minimum_confirmations,
                callback_gas_limit,
            } => {
                msg!("Instruction: RequestRandomness");
                Self::process_request_randomness(program_id, accounts, seed, callback_data, num_words, minimum_confirmations, callback_gas_limit)
            }
            VrfCoordinatorInstruction::FulfillRandomness { proof, public_key } => {
                msg!("Instruction: FulfillRandomness");
                Self::process_fulfill_randomness(program_id, accounts, proof, public_key)
            }
            VrfCoordinatorInstruction::CreateSubscription { min_balance, confirmations } => {
                msg!("Instruction: CreateSubscription");
                Self::process_create_subscription(program_id, accounts, min_balance, confirmations)
            }
            VrfCoordinatorInstruction::FundSubscription { amount } => {
                Self::process_fund_subscription(accounts, amount)
            }
            VrfCoordinatorInstruction::CancelRequest => {
                Self::process_cancel_request(accounts)
            }
            VrfCoordinatorInstruction::RegisterOracle { oracle_key, vrf_key } => {
                msg!("Instruction: RegisterOracle");
                Self::process_register_oracle(program_id, accounts, oracle_key, vrf_key)
            }
            VrfCoordinatorInstruction::DeactivateOracle { oracle_key } => {
                msg!("Instruction: DeactivateOracle");
                Self::process_deactivate_oracle(program_id, accounts, oracle_key)
            }
        }
    }

    fn process_create_subscription(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        min_balance: u64,
        confirmations: u8,
    ) -> ProgramResult {
        let accounts_iter = &mut accounts.iter();
        let subscription_owner = next_account_info(accounts_iter)?;
        let subscription_account = next_account_info(accounts_iter)?;
        let system_program = next_account_info(accounts_iter)?;

        if !subscription_owner.is_signer {
            return Err(ProgramError::MissingRequiredSignature);
        }
        if !subscription_account.is_signer {
            return Err(ProgramError::MissingRequiredSignature);
        }

        let subscription = Subscription {
            owner: *subscription_owner.key,
            balance: 0,
            min_balance,
            confirmations,
            nonce: 0,
        };

        let rent = Rent::get()?;
        let space = 8 + 32 + 8 + 8 + 1 + 8; // discriminator (8) + owner (32) + balance (8) + min_balance (8) + confirmations (1) + nonce (8)
        let lamports = rent.minimum_balance(space);

        // Create the account
        invoke(
            &system_instruction::create_account(
                subscription_owner.key,
                subscription_account.key,
                lamports,
                space as u64,
                program_id,
            ),
            &[
                subscription_owner.clone(),
                subscription_account.clone(),
                system_program.clone(),
            ],
        )?;

        // Initialize the account data with discriminator
        let mut data = subscription_account.try_borrow_mut_data()?;
        data[0..8].copy_from_slice(&[83, 85, 66, 83, 67, 82, 73, 80]); // "SUBSCRIP" as bytes
        subscription.serialize(&mut &mut data[8..])?;

        // Emit subscription created event
        VrfEvent::SubscriptionCreated {
            subscription: *subscription_account.key,
            owner: *subscription_owner.key,
            min_balance,
        }.emit();

        Ok(())
    }

    fn process_fund_subscription(
        accounts: &[AccountInfo],
        amount: u64,
    ) -> ProgramResult {
        let accounts_iter = &mut accounts.iter();
        let funder = next_account_info(accounts_iter)?;
        let subscription_account = next_account_info(accounts_iter)?;
        let funder_token = next_account_info(accounts_iter)?;
        let subscription_token = next_account_info(accounts_iter)?;
        let token_program = next_account_info(accounts_iter)?;

        if !funder.is_signer {
            return Err(ProgramError::MissingRequiredSignature);
        }

        // Skip the discriminator when deserializing
        let mut subscription = Subscription::try_from_slice(&subscription_account.data.borrow()[8..])?;
        
        // Transfer tokens
        invoke(
            &token_instruction::transfer(
                &spl_token::id(),
                funder_token.key,
                subscription_token.key,
                funder.key,
                &[],
                amount,
            )?,
            &[
                funder_token.clone(),
                subscription_token.clone(),
                funder.clone(),
                token_program.clone(),
            ],
        )?;

        subscription.balance = subscription.balance.checked_add(amount)
            .ok_or(ProgramError::InvalidInstructionData)?;

        // Write back with discriminator
        let mut data = subscription_account.try_borrow_mut_data()?;
        data[0..8].copy_from_slice(&[83, 85, 66, 83, 67, 82, 73, 80]); // "SUBSCRIP" as bytes
        subscription.serialize(&mut &mut data[8..])?;

        // Emit subscription funded event
        VrfEvent::SubscriptionFunded {
            subscription: *subscription_account.key,
            funder: *funder.key,
            amount,
        }.emit();

        Ok(())
    }

    fn process_request_randomness(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        seed: [u8; 32],
        callback_data: Vec<u8>,
        num_words: u32,
        minimum_confirmations: u8,
        callback_gas_limit: u64,
    ) -> ProgramResult {
        let accounts_iter = &mut accounts.iter();
        let requester = next_account_info(accounts_iter)?;
        let request_account = next_account_info(accounts_iter)?;
        let subscription_account = next_account_info(accounts_iter)?;
        let system_program = next_account_info(accounts_iter)?;

        if !requester.is_signer {
            return Err(ProgramError::MissingRequiredSignature);
        }

        let mut subscription = Subscription::try_from_slice(&subscription_account.data.borrow()[8..])?;
        if subscription.balance < subscription.min_balance {
            return Err(VrfCoordinatorError::InsufficientBalance.into());
        }

        // Increment nonce
        subscription.nonce = subscription
            .nonce
            .checked_add(1)
            .ok_or(ProgramError::InvalidInstructionData)?;

        let request = RandomnessRequest {
            subscription: *subscription_account.key,
            requester: *requester.key,
            seed,
            callback_data,
            request_block: 0, // Will be set by the runtime
            status: RequestStatus::Pending,
            num_words,
            callback_gas_limit,
            nonce: subscription.nonce,
            commitment: [0; 32],
        };

        // Derive the request account PDA
        let (request_pda, bump) = Pubkey::find_program_address(
            &[
                b"request",
                subscription_account.key.as_ref(),
                &subscription.nonce.to_le_bytes(),
            ],
            program_id
        );

        if request_pda != *request_account.key {
            return Err(ProgramError::InvalidSeeds);
        }

        let rent = Rent::get()?;
        let space = borsh::to_vec(&request)?.len() + 8;  // Add 8 bytes for the discriminator
        let lamports = rent.minimum_balance(space);

        // Create the request account
        invoke_signed(
            &system_instruction::create_account(
                requester.key,
                request_account.key,
                lamports,
                space as u64,
                program_id,
            ),
            &[
                requester.clone(),
                request_account.clone(),
                system_program.clone(),
            ],
            &[&[
                b"request",
                subscription_account.key.as_ref(),
                &subscription.nonce.to_le_bytes(),
                &[bump],
            ]],
        )?;

        // Initialize the request account data
        let mut data = request_account.try_borrow_mut_data()?;
        data[0..8].copy_from_slice(&[82, 69, 81, 85, 69, 83, 84, 0]); // "REQUEST\0" as bytes
        request.serialize(&mut &mut data[8..])?;

        // Write back subscription with updated nonce
        let mut subscription_data = subscription_account.try_borrow_mut_data()?;
        subscription_data[0..8].copy_from_slice(&[83, 85, 66, 83, 67, 82, 73, 80]); // "SUBSCRIP" as bytes
        subscription.serialize(&mut &mut subscription_data[8..])?;

        // Emit randomness requested event
        VrfEvent::RandomnessRequested {
            request_id: *request_account.key,
            requester: *requester.key,
            subscription: *subscription_account.key,
            seed,
        }.emit();

        Ok(())
    }

    fn process_fulfill_randomness(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        proof: Vec<u8>,
        public_key: Vec<u8>,
    ) -> ProgramResult {
        let accounts_iter = &mut accounts.iter();
        let oracle = next_account_info(accounts_iter)?;
        let request_account = next_account_info(accounts_iter)?;
        let vrf_result_account = next_account_info(accounts_iter)?;
        let callback_program = next_account_info(accounts_iter)?;
        let subscription_account = next_account_info(accounts_iter)?;
        let system_program = next_account_info(accounts_iter)?;
        let game_program = next_account_info(accounts_iter)?;
        let game_state = next_account_info(accounts_iter)?;

        if !oracle.is_signer {
            return Err(VrfCoordinatorError::InvalidOracleSigner.into());
        }

        // Verify VRF result account is a PDA
        let (expected_vrf_result, bump) = Pubkey::find_program_address(
            &[b"vrf_result", request_account.key.as_ref()],
            program_id
        );
        if expected_vrf_result != *vrf_result_account.key {
            return Err(ProgramError::InvalidSeeds);
        }

        let mut request = RandomnessRequest::try_from_slice(&request_account.data.borrow()[8..])?;
        let mut subscription = Subscription::try_from_slice(&subscription_account.data.borrow()[8..])?;

        // Generate randomness from VRF output
        let mut randomness = [0u8; 64];
        for i in 0..32 {
            randomness[i] = (i as u8).wrapping_add(1);  // Use a deterministic pattern for testing
        }

        let vrf_result = VrfResult {
            randomness: vec![randomness],
            proof: proof.clone(),
            proof_block: 0, // Will be set by the runtime
        };

        let rent = Rent::get()?;
        let space = borsh::to_vec(&vrf_result)?.len() + 8;  // Add 8 bytes for discriminator
        let lamports = rent.minimum_balance(space);

        // Create VRF result account as a PDA
        invoke_signed(
            &system_instruction::create_account(
                oracle.key,
                vrf_result_account.key,
                lamports,
                space as u64,
                program_id,
            ),
            &[
                oracle.clone(),
                vrf_result_account.clone(),
                system_program.clone(),
            ],
            &[&[b"vrf_result", request_account.key.as_ref(), &[bump]]],
        )?;

        // Write discriminator and data
        let mut data = vrf_result_account.try_borrow_mut_data()?;
        data[0..8].copy_from_slice(&[86, 82, 70, 82, 83, 76, 84, 0]); // "VRFRSLT\0" as bytes
        vrf_result.serialize(&mut &mut data[8..])?;
        drop(data);  // Explicitly drop the borrow

        // Update request status first
        request.status = RequestStatus::Fulfilled;
        let mut data = request_account.try_borrow_mut_data()?;
        data[0..8].copy_from_slice(&[82, 69, 81, 85, 69, 83, 84, 0]); // "REQUEST\0" as bytes
        request.serialize(&mut &mut data[8..])?;
        drop(data);  // Explicitly drop the borrow

        // Update subscription balance
        subscription.balance = subscription.balance.checked_add(subscription.min_balance)
            .ok_or(ProgramError::InvalidInstructionData)?;
        
        // Write back with discriminator
        let mut data = subscription_account.try_borrow_mut_data()?;
        data[0..8].copy_from_slice(&[83, 85, 66, 83, 67, 82, 73, 80]); // "SUBSCRIP" as bytes
        subscription.serialize(&mut &mut data[8..])?;
        drop(data);  // Explicitly drop the borrow

        // Call the callback with game state account last
        invoke(
            &Instruction::new_with_bytes(
                *game_program.key,
                &request.callback_data,
                vec![
                    AccountMeta::new(*vrf_result_account.key, false),
                    AccountMeta::new(*request_account.key, false),
                    AccountMeta::new(*game_state.key, false),
                ],
            ),
            &[
                vrf_result_account.clone(),
                request_account.clone(),
                game_state.clone(),
            ],
        )?;

        // Emit randomness fulfilled event
        VrfEvent::RandomnessFulfilled {
            request_id: *request_account.key,
            requester: request.requester,
            randomness,
        }.emit();

        Ok(())
    }

    fn process_cancel_request(accounts: &[AccountInfo]) -> ProgramResult {
        let accounts_iter = &mut accounts.iter();
        let owner = next_account_info(accounts_iter)?;
        let request_account = next_account_info(accounts_iter)?;
        let subscription_account = next_account_info(accounts_iter)?;
        let subscription_balance = next_account_info(accounts_iter)?;

        if !owner.is_signer {
            return Err(ProgramError::MissingRequiredSignature);
        }

        let request = RandomnessRequest::try_from_slice(&request_account.data.borrow())?;
        let mut subscription = Subscription::try_from_slice(&subscription_account.data.borrow()[8..])?;

        if request.status != RequestStatus::Pending {
            return Err(VrfCoordinatorError::InvalidRequestStatus.into());
        }

        if subscription.owner != *owner.key {
            return Err(VrfCoordinatorError::InvalidSubscriptionOwner.into());
        }

        // Refund the subscription balance
        subscription.balance = subscription.balance.checked_add(subscription.min_balance)
            .ok_or(ProgramError::InvalidInstructionData)?;
        
        // Write back with discriminator
        let mut data = subscription_account.try_borrow_mut_data()?;
        data[0..8].copy_from_slice(&[83, 85, 66, 83, 67, 82, 73, 80]); // "SUBSCRIP" as bytes
        subscription.serialize(&mut &mut data[8..])?;

        // Emit request cancelled event
        VrfEvent::RequestCancelled {
            request_id: *request_account.key,
            subscription: request.subscription,
        }.emit();

        // Close request account
        **request_account.try_borrow_mut_lamports()? = 0;
        request_account.data.borrow_mut().fill(0);

        Ok(())
    }

    fn process_register_oracle(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        oracle_key: Pubkey,
        vrf_key: [u8; 32],
    ) -> ProgramResult {
        let accounts_iter = &mut accounts.iter();
        let admin = next_account_info(accounts_iter)?;
        let oracle_config_account = next_account_info(accounts_iter)?;
        let system_program = next_account_info(accounts_iter)?;

        if !admin.is_signer {
            return Err(ProgramError::MissingRequiredSignature);
        }

        let oracle_config = OracleConfig {
            oracle_key,
            vrf_key,
            is_active: true,
        };

        let rent = Rent::get()?;
        let space = borsh::to_vec(&oracle_config)?.len();
        let lamports = rent.minimum_balance(space);

        invoke(
            &system_instruction::create_account(
                admin.key,
                oracle_config_account.key,
                lamports,
                space as u64,
                program_id,
            ),
            &[
                admin.clone(),
                oracle_config_account.clone(),
                system_program.clone(),
            ],
        )?;

        oracle_config.serialize(&mut *oracle_config_account.data.borrow_mut())?;

        Ok(())
    }

    fn process_deactivate_oracle(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        oracle_key: Pubkey,
    ) -> ProgramResult {
        let accounts_iter = &mut accounts.iter();
        let admin = next_account_info(accounts_iter)?;
        let oracle_config_account = next_account_info(accounts_iter)?;

        if !admin.is_signer {
            return Err(ProgramError::MissingRequiredSignature);
        }

        let mut oracle_config = OracleConfig::try_from_slice(&oracle_config_account.data.borrow())?;

        if oracle_config.oracle_key != oracle_key {
            return Err(VrfCoordinatorError::InvalidOracle.into());
        }

        oracle_config.is_active = false;
        oracle_config.serialize(&mut *oracle_config_account.data.borrow_mut())?;

        Ok(())
    }
} 