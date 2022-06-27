use thiserror::Error;

#[derive(Error, Debug)]
pub enum P8eEncryptionError {
    #[error("Unspecified p8e encryption error")]
    Unspecified,
    #[error("Encryption error")]
    EncryptionError,
    #[error("Decryption error")]
    DecryptionError,
    #[error("HKDF key derivation error")]
    HkdfError,
    #[error("Error decoding the public key")]
    PublicKeyDecodingError,
    #[error("Error decoding the private key")]
    PrivateKeyDecodingError,
}
