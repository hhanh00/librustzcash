//! The Issue fields of a PCZT (ZSA only).
//!
//! This module defines the PCZT wire format for ZSA issuance bundles,
//! enabling collaborative construction of asset issuance transactions.

use alloc::vec::Vec;

use serde::{Deserialize, Serialize};
use serde_with::serde_as;

/// PCZT fields specific to the issue bundle (if any).
///
/// This represents an issue bundle in a partially-created transaction.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Bundle {
    /// The raw bytes of the issue validating key.
    pub ik: [u8; 32],

    /// The issue actions in this bundle.
    #[serde(default)]
    pub actions: Vec<IssueAction>,
}

#[cfg(all(feature = "orchard", zcash_unstable = "nu7"))]
impl Bundle {
    /// Returns `true` if this bundle contains any issuance data.
    pub fn is_initialized(&self) -> bool {
        !self.actions.is_empty()
    }

    /// Deserializes this wire-format bundle into an `IssueBundle<AwaitingSighash>`.
    ///
    /// Uses the rho values stored in the wire format (derived from the first
    /// Orchard nullifier per ZIP-227).
    ///
    /// Returns `None` if the wire data is empty or invalid.
    pub fn to_awaiting_sighash(
        &self,
    ) -> Option<orchard::issuance::IssueBundle<orchard::issuance::AwaitingSighash>> {
        if self.actions.is_empty() {
            return None;
        }

        use orchard::issuance::{
            IssueAction, IssueBundle, IssuanceFlags,
            auth::IssueValidatingKey,
        };
        use orchard::note::{AssetBase, RandomSeed, Rho};
        use nonempty::NonEmpty;

        let ik = IssueValidatingKey::<orchard::issuance::auth::ZSASchnorr>::from_bytes(&self.ik)?;
        let actions: Option<Vec<IssueAction>> = self.actions.iter().map(|a| {
            let notes: Option<Vec<orchard::Note>> = a.notes.iter().map(|n| {
                let recipient = orchard::Address::from_raw_address_bytes(&n.recipient).into_option()?;
                let asset = AssetBase::from_bytes(&n.asset).into_option()?;
                let rho = Rho::from_bytes(&n.rho).into_option()?;
                let rseed = RandomSeed::from_bytes(n.rseed, &rho).into_option()?;
                orchard::Note::from_parts(recipient, orchard::value::NoteValue::from_raw(n.value), asset, rho, rseed).into_option()
            }).collect();
            let flags = IssuanceFlags::from_byte(a.flags)?;
            Some(IssueAction::from_parts(a.asset_desc_hash, notes?, flags.finalize()))
        }).collect();
        let actions = NonEmpty::from_vec(actions?)?;
        Some(IssueBundle::from_parts(ik, actions, orchard::issuance::AwaitingSighash))
    }
}

impl Bundle {
    /// Merges this bundle with another.
    ///
    /// Returns the merged bundle. If both bundles have an `ik`, they must match.
    /// Actions are concatenated.
    pub fn merge(&self, other: &Self) -> Self {
        if self.ik == [0u8; 32] {
            return other.clone();
        }
        if other.ik == [0u8; 32] {
            return self.clone();
        }
        // Both have ik values; they must match
        if self.ik != other.ik {
            // In case of conflict, return self (the first bundle takes precedence)
            return self.clone();
        }
        let mut actions = self.actions.clone();
        actions.extend(other.actions.clone());
        Self {
            ik: self.ik,
            actions,
        }
    }
}

/// An individual issuance action within a PCZT issue bundle.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IssueAction {
    /// The asset description hash for this issuance.
    pub asset_desc_hash: [u8; 32],

    /// The notes being issued in this action.
    #[serde(default)]
    pub notes: Vec<IssueNote>,

    /// Issuance flags (see ZIP-230).
    /// Bit 0: finalize flag.
    pub flags: u8,
}

/// A note within an issuance action.
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IssueNote {
    /// The recipient address (raw bytes).
    #[serde_as(as = "[_; 43]")]
    pub recipient: [u8; 43],

    /// The value of the issued note.
    pub value: u64,

    /// The asset base for this note (32 bytes).
    pub asset: [u8; 32],

    /// The random seed for the note (used to reconstruct the note).
    #[serde_as(as = "[_; 32]")]
    pub rseed: [u8; 32],

    /// The rho value for this note (derived from the first Orchard nullifier
    /// per ZIP-227).
    #[serde_as(as = "[_; 32]")]
    pub rho: [u8; 32],

    /// The note commitment (cmx).
    pub cmx: [u8; 32],

    /// The ephemeral public key for the encrypted note.
    pub ephemeral_key: [u8; 32],

    /// The encrypted note ciphertext.
    pub enc_ciphertext: Vec<u8>,

    /// The outgoing ciphertext.
    pub out_ciphertext: Vec<u8>,
}
