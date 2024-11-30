#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid id length")]
    InvalidLength,
    #[error("openssl: {0}")]
    Openssl(#[from] openssl::error::ErrorStack),
}
