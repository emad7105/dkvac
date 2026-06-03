use thiserror::Error;

#[derive(Debug, Error)]
pub enum DkvacError {
    #[error("invalid proof")]
    InvalidProof,
    #[error("invalid attribute set")]
    InvalidAttributeSet,
    #[error("invalid delegation")]
    InvalidDelegation,
    #[error("invalid disclosure")]
    InvalidDisclosure,
    #[error("identity point not allowed")]
    IdentityPoint,
    #[error("index out of range")]
    IndexOutOfRange,
}
