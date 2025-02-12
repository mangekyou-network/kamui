use {
    borsh::{BorshDeserialize, BorshSerialize},
    solana_program::{msg, pubkey::Pubkey},
    base64::Engine,
};

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub enum VrfEvent {
    RandomnessRequested {
        request_id: Pubkey,
        requester: Pubkey,
        subscription: Pubkey,
        seed: [u8; 32],
    },
    RandomnessFulfilled {
        request_id: Pubkey,
        requester: Pubkey,
        randomness: [u8; 64],
    },
    SubscriptionCreated {
        subscription: Pubkey,
        owner: Pubkey,
        min_balance: u64,
    },
    SubscriptionFunded {
        subscription: Pubkey,
        funder: Pubkey,
        amount: u64,
    },
    RequestCancelled {
        request_id: Pubkey,
        subscription: Pubkey,
    },
}

impl VrfEvent {
    pub fn emit(&self) {
        let data = borsh::to_vec(self).unwrap();
        let b64 = base64::engine::general_purpose::STANDARD.encode(&data);
        msg!("VRF_EVENT:{}", b64);
    }
} 