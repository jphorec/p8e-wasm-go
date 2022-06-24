use thiserror::Error;

#[derive(Error, Debug)]
pub enum DIMEError {
    #[error("Unspecified DIME Error")]
    Unspecified,
    #[error("DIME encryption error")]
    EncryptionError,
    #[error("DIME decryption error")]
    DecryptionError,
    #[error("DIME HKDF Key Derivation error")]
    HkdfError,
    #[error("Error decoding the public key")]
    PublicKeyDecodingError,
    #[error("Error decoding the private key")]
    PrivateKeyDecodingError,
}
