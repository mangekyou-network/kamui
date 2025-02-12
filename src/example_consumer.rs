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

    let mut state = GameState::try_from_slice(&game_state.data.borrow()[8..])?;  // Skip discriminator
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

    // Update and write back game state
    state.is_pending = true;
    let mut data = game_state.try_borrow_mut_data()?;
    data[0..8].copy_from_slice(&[71, 65, 77, 69, 83, 84, 65, 84]); // "GAMESTAT" as bytes
    state.serialize(&mut &mut data[8..])?;

    Ok(())
}