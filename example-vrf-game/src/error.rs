use {
    solana_program::program_error::ProgramError,
    thiserror::Error,
};

#[derive(Error, Debug, Copy, Clone)]
pub enum GameError {
    #[error("Game is already pending randomness")]
    AlreadyPending,
    #[error("Invalid game owner")]
    InvalidOwner,
    #[error("Invalid VRF coordinator program")]
    InvalidVrfCoordinator,
    #[error("Invalid VRF result account")]
    InvalidVrfResult,
    #[error("Invalid VRF request account")]
    InvalidVrfRequest,
}

impl From<GameError> for ProgramError {
    fn from(e: GameError) -> Self {
        ProgramError::Custom(e as u32)
    }
} 