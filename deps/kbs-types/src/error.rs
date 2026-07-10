use thiserror::Error;

pub type Result<T> = core::result::Result<T, KbsTypesError>;

#[derive(Error, Debug)]
pub enum KbsTypesError {
    #[error("Serialize/Deserialize error")]
    Serde,
}
