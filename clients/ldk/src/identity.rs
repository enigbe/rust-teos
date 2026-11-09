use lightning::bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use teos_common::{cryptography, UserId};

/// A persisted signing identity used to authenticate with TEOS towers.
///
/// Obtain this from [`crate::ClientStore::load_or_create_identity`]. The secret
/// key is kept private; callers can access the public identity and sign messages.
pub struct ClientIdentity {
    secret_key: SecretKey,
}

impl ClientIdentity {
    pub(crate) fn new(secret_key: SecretKey) -> Self {
        Self { secret_key }
    }

    /// Returns the public key to register with a tower.
    pub fn user_id(&self) -> UserId {
        UserId(PublicKey::from_secret_key(
            &Secp256k1::new(),
            &self.secret_key,
        ))
    }

    /// Signs a message using the Lightning message-signing format used by TEOS.
    pub fn sign(&self, message: &[u8]) -> String {
        cryptography::sign(message, &self.secret_key)
    }
}
