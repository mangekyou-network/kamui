use solana_program::program_error::ProgramError;
use thiserror::Error;

#[derive(Error, Debug, Copy, Clone)]
pub enum VrfCoordinatorError {
    #[error("Invalid instruction")]
    InvalidInstruction,

    #[error("Not rent exempt")]
    NotRentExempt,

    #[error("Insufficient balance")]
    InsufficientBalance,

    #[error("Invalid subscription owner")]
    InvalidSubscriptionOwner,

    #[error("Invalid request status")]
    InvalidRequestStatus,

    #[error("Invalid oracle signer")]
    InvalidOracleSigner,

    #[error("Invalid VRF proof")]
    InvalidVrfProof,

    #[error("Request already fulfilled")]
    RequestAlreadyFulfilled,

    #[error("Insufficient confirmations")]
    InsufficientConfirmations,

    #[error("Invalid request confirmations")]
    InvalidRequestConfirmations,

    #[error("Invalid callback gas limit")]
    InvalidCallbackGasLimit,

    #[error("Invalid number of words")]
    InvalidNumberOfWords,

    #[error("Invalid oracle")]
    InvalidOracle,

    #[error("Invalid commitment")]
    InvalidCommitment,

    #[error("Callback failed")]
    CallbackFailed,

    #[error("Request expired")]
    RequestExpired,

    #[error("Invalid request parameters")]
    InvalidRequestParameters,
}

impl From<VrfCoordinatorError> for ProgramError {
    fn from(e: VrfCoordinatorError) -> Self {
        ProgramError::Custom(e as u32)
    }
} 