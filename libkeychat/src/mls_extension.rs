//! Nostr Group Extension functionality for MLS Group Context.
//! This is a required extension for Nostr Groups as per NIP-104.
//! Inlined from the keychat-io/openmls kc4 fork's `kc` crate.

use openmls::prelude::*;
use rand::Rng;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tls_codec::{TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSerializeBytes, TlsSize};

/// Errors that can occur when working with the Nostr Group Data Extension.
#[derive(Debug, Error)]
pub enum NostrGroupDataExtensionError {
    #[error("Failed to deserialize extension: {0}")]
    TlsDeserializeError(String),

    #[error("Unexpected extension type")]
    UnexpectedExtensionType,

    #[error("Nostr group data extension not found")]
    NostrGroupDataExtensionNotFound,
}

/// This is an MLS Group Context extension used to store the group's name,
/// description, ID, and admin identities.
#[derive(
    PartialEq,
    Eq,
    Clone,
    Debug,
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSerializeBytes,
    TlsSize,
)]
pub struct NostrGroupDataExtension {
    pub nostr_group_id: [u8; 32],
    pub name: Vec<u8>,
    pub description: Vec<u8>,
    pub admin_pubkeys: Vec<Vec<u8>>,
    pub relays: Vec<Vec<u8>>,
    pub status: Vec<u8>,
}

impl NostrGroupDataExtension {
    pub fn extension_type(&self) -> u16 {
        0xF233
    }

    /// Creates a new NostrGroupDataExtension with the given parameters.
    pub fn new(
        name: String,
        description: String,
        admin_pubkeys_hex: Vec<String>,
        relays: Vec<String>,
        status: String,
    ) -> Self {
        let mut rng = rand::rng();
        let random_bytes: [u8; 32] = rng.random();

        Self {
            nostr_group_id: random_bytes,
            name: name.into_bytes(),
            description: description.into_bytes(),
            admin_pubkeys: admin_pubkeys_hex
                .into_iter()
                .map(|identity| identity.into_bytes())
                .collect(),
            relays: relays.into_iter().map(|relay| relay.into_bytes()).collect(),
            status: status.into_bytes(),
        }
    }

    /// Attempts to extract and deserialize a NostrGroupDataExtension from a
    /// GroupContext.
    pub fn from_group_context(
        group_context: &GroupContext,
    ) -> Result<Self, NostrGroupDataExtensionError> {
        let group_data_extension = match group_context
            .extensions()
            .iter()
            .find(|ext| ext.extension_type() == ExtensionType::Unknown(0xF233))
        {
            Some(Extension::Unknown(_, ext)) => ext,
            Some(_) => return Err(NostrGroupDataExtensionError::UnexpectedExtensionType),
            None => return Err(NostrGroupDataExtensionError::NostrGroupDataExtensionNotFound),
        };

        let (deserialized, _) = Self::tls_deserialize_bytes(&group_data_extension.0)
            .map_err(|e| NostrGroupDataExtensionError::TlsDeserializeError(e.to_string()))?;

        Ok(deserialized)
    }

    /// Attempts to extract and deserialize a NostrGroupDataExtension from an
    /// MlsGroup.
    pub fn from_group(group: &MlsGroup) -> Result<Self, NostrGroupDataExtensionError> {
        let group_data_extension = match group
            .extensions()
            .iter()
            .find(|ext| ext.extension_type() == ExtensionType::Unknown(0xF233))
        {
            Some(Extension::Unknown(_, ext)) => ext,
            Some(_) => return Err(NostrGroupDataExtensionError::UnexpectedExtensionType),
            None => return Err(NostrGroupDataExtensionError::NostrGroupDataExtensionNotFound),
        };

        let (deserialized, _) = Self::tls_deserialize_bytes(&group_data_extension.0)
            .map_err(|e| NostrGroupDataExtensionError::TlsDeserializeError(e.to_string()))?;

        Ok(deserialized)
    }

    /// Returns the group ID as a hex-encoded string.
    pub fn nostr_group_id(&self) -> String {
        hex::encode(self.nostr_group_id)
    }

    /// Sets the group ID using a 32-byte array.
    pub fn set_nostr_group_id(&mut self, nostr_group_id: [u8; 32]) {
        self.nostr_group_id = nostr_group_id;
    }

    /// Returns the group name as a UTF-8 string.
    pub fn name(&self) -> String {
        String::from_utf8_lossy(&self.name).to_string()
    }

    /// Sets the group name.
    pub fn set_name(&mut self, name: String) {
        self.name = name.into_bytes();
    }

    /// Returns the group status as a UTF-8 string.
    pub fn status(&self) -> String {
        String::from_utf8_lossy(&self.status).to_string()
    }

    /// Sets the group status.
    pub fn set_status(&mut self, status: String) {
        self.status = status.into_bytes();
    }

    /// Returns the group description as a UTF-8 string.
    pub fn description(&self) -> String {
        String::from_utf8_lossy(&self.description).to_string()
    }

    /// Sets the group description.
    pub fn set_description(&mut self, description: String) {
        self.description = description.into_bytes();
    }

    /// Returns the list of admin identities as UTF-8 strings.
    pub fn admin_pubkeys(&self) -> Vec<String> {
        self.admin_pubkeys
            .iter()
            .map(|identity| String::from_utf8_lossy(identity).to_string())
            .collect()
    }

    /// Sets the complete list of admin pubkeys.
    pub fn set_admin_pubkeys(&mut self, admin_pubkeys_hex: Vec<String>) {
        self.admin_pubkeys = admin_pubkeys_hex
            .into_iter()
            .map(|identity| identity.into_bytes())
            .collect();
    }

    /// Adds a new admin identity to the list.
    pub fn add_admin_pubkey(&mut self, admin_pubkey_hex: String) {
        self.admin_pubkeys.push(admin_pubkey_hex.into_bytes());
    }

    /// Removes an admin identity from the list if it exists.
    pub fn remove_admin_pubkey(&mut self, admin_pubkey_hex: String) {
        let admin_bytes = admin_pubkey_hex.into_bytes();
        self.admin_pubkeys
            .retain(|identity| identity != &admin_bytes);
    }

    /// Returns the list of relay URLs as UTF-8 strings.
    pub fn relays(&self) -> Vec<String> {
        self.relays
            .iter()
            .map(|relay| String::from_utf8_lossy(relay).to_string())
            .collect()
    }

    /// Sets the complete list of relay URLs.
    pub fn set_relays(&mut self, relays: Vec<String>) {
        self.relays = relays.into_iter().map(|relay| relay.into_bytes()).collect();
    }

    /// Adds a new relay URL to the list.
    pub fn add_relay(&mut self, relay: String) {
        self.relays.push(relay.into_bytes());
    }

    /// Removes a relay URL from the list if it exists.
    pub fn remove_relay(&mut self, relay: String) {
        let relay_bytes = relay.into_bytes();
        self.relays.retain(|r| r != &relay_bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_extension() -> NostrGroupDataExtension {
        NostrGroupDataExtension::new(
            "Test Group".to_string(),
            "Test Description".to_string(),
            vec!["admin1".to_string(), "admin2".to_string()],
            vec![
                "wss://relay1.com".to_string(),
                "wss://relay2.com".to_string(),
            ],
            "active".to_string(),
        )
    }

    #[test]
    fn test_new_and_getters() {
        let extension = create_test_extension();
        assert_eq!(extension.nostr_group_id.len(), 32);
        assert_eq!(extension.name(), "Test Group");
        assert_eq!(extension.description(), "Test Description");
        assert_eq!(extension.admin_pubkeys(), vec!["admin1", "admin2"]);
        assert_eq!(
            extension.relays(),
            vec!["wss://relay1.com", "wss://relay2.com"]
        );
        assert_eq!(extension.status(), "active");
    }

    #[test]
    fn test_group_id_operations() {
        let mut extension = create_test_extension();
        let new_id = [42u8; 32];
        extension.set_nostr_group_id(new_id);
        assert_eq!(extension.nostr_group_id(), hex::encode(new_id));
    }

    #[test]
    fn test_name_operations() {
        let mut extension = create_test_extension();
        extension.set_name("New Name".to_string());
        assert_eq!(extension.name(), "New Name");
    }

    #[test]
    fn test_description_operations() {
        let mut extension = create_test_extension();
        extension.set_description("New Description".to_string());
        assert_eq!(extension.description(), "New Description");
    }

    #[test]
    fn test_admin_pubkey_operations() {
        let mut extension = create_test_extension();
        extension.add_admin_pubkey("admin3".to_string());
        assert_eq!(
            extension.admin_pubkeys(),
            vec!["admin1", "admin2", "admin3"]
        );
        extension.remove_admin_pubkey("admin2".to_string());
        assert_eq!(extension.admin_pubkeys(), vec!["admin1", "admin3"]);
        extension.set_admin_pubkeys(vec!["newadmin1".to_string(), "newadmin2".to_string()]);
        assert_eq!(extension.admin_pubkeys(), vec!["newadmin1", "newadmin2"]);
    }

    #[test]
    fn test_relay_operations() {
        let mut extension = create_test_extension();
        extension.add_relay("wss://relay3.com".to_string());
        assert_eq!(
            extension.relays(),
            vec!["wss://relay1.com", "wss://relay2.com", "wss://relay3.com"]
        );
        extension.remove_relay("wss://relay2.com".to_string());
        assert_eq!(
            extension.relays(),
            vec!["wss://relay1.com", "wss://relay3.com"]
        );
        extension.set_relays(vec![
            "wss://new1.com".to_string(),
            "wss://new2.com".to_string(),
        ]);
        assert_eq!(extension.relays(), vec!["wss://new1.com", "wss://new2.com"]);
    }

    #[test]
    fn test_extension_type() {
        let extension = create_test_extension();
        assert_eq!(extension.extension_type(), 0xF233);
    }
}
