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

    /// Pending issuance intents. These are populated before the Issuer builds
    /// the [`IssueBundle`] and are cleared once the bundle is built.
    ///
    /// Intents and actions are logically exclusive: intents represent the "what
    /// to issue" plan, and actions represent the built (or signed) bundle.
    #[serde(default)]
    pub intents: Vec<IssueIntent>,

    /// The issue actions in this bundle.
    #[serde(default)]
    pub actions: Vec<IssueAction>,
}

#[cfg(all(feature = "orchard", zcash_unstable = "nu7"))]
impl Bundle {
    /// Returns `true` if this bundle contains any issuance data.
    pub fn is_initialized(&self) -> bool {
        !self.actions.is_empty() || !self.intents.is_empty()
    }

    /// Returns `true` if there are pending issuance intents.
    pub fn has_intents(&self) -> bool {
        !self.intents.is_empty()
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
        to_issue_bundle(self, orchard::issuance::AwaitingSighash)
    }

    /// Deserializes this wire-format bundle into an `IssueBundle<Signed>`.
    ///
    /// Requires that the signature bytes are present in the wire format
    /// (stored by the Issuer's sign phase).
    ///
    /// Returns `None` if the wire data is empty, invalid, or missing a signature.
    pub fn to_signed(
        &self,
    ) -> Option<orchard::issuance::IssueBundle<orchard::issuance::Signed>> {
        use orchard::issuance::auth::IssueAuthSig;
        use orchard::issuance::sighash_kind::{BIP340IssueAuthSig, IssueSighashKind};
        let sig_bytes = self.actions.first()?.sig_bytes.clone();
        if sig_bytes.is_empty() {
            return None;
        }
        let auth_sig = IssueAuthSig::<orchard::issuance::auth::ZSASchnorr>::decode(&sig_bytes).ok()?;
        let sig = BIP340IssueAuthSig::new(IssueSighashKind::AllEffecting, auth_sig);
        let auth = orchard::issuance::Signed::new(sig);
        to_issue_bundle(self, auth)
    }
}

/// Shared helper to reconstruct an `IssueBundle` from the wire format.
#[cfg(all(feature = "orchard", zcash_unstable = "nu7"))]
fn to_issue_bundle<T: orchard::issuance::IssueAuth>(
    wire: &Bundle,
    auth: T,
) -> Option<orchard::issuance::IssueBundle<T>> {
    use orchard::issuance::{
        IssueAction, IssueBundle, IssuanceFlags,
        auth::IssueValidatingKey,
    };
    use orchard::note::{AssetBase, RandomSeed, Rho};
    use nonempty::NonEmpty;

    if wire.actions.is_empty() {
        return None;
    }

    let ik = IssueValidatingKey::<orchard::issuance::auth::ZSASchnorr>::from_bytes(&wire.ik)?;
    let actions: Option<Vec<IssueAction>> = wire.actions.iter().map(|a| {
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
    Some(IssueBundle::from_parts(ik, actions, auth))
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
        let mut intents = self.intents.clone();
        intents.extend(other.intents.clone());
        let mut actions = self.actions.clone();
        actions.extend(other.actions.clone());
        Self {
            ik: self.ik,
            intents,
            actions,
        }
    }
}

/// A user-specified intent to issue a ZSA asset.
///
/// Intents are serialized into the PCZT before the Issuer builds the
/// `IssueBundle<AwaitingSighash>`. Once the bundle is built, intents
/// are cleared and the resulting notes are stored in [`Bundle::actions`].
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IssueIntent {
    /// The asset description hash for this issuance.
    pub asset_desc_hash: [u8; 32],

    /// The recipient address (raw bytes, 43 bytes).
    #[serde_as(as = "[_; 43]")]
    pub recipient: [u8; 43],

    /// The value to issue for this asset.
    pub value: u64,

    /// Whether this is the first issuance of this asset.
    pub first_issuance: bool,

    /// Whether to finalize this asset after issuance.
    #[serde(default)]
    pub finalize: bool,
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

    /// The issuance authorization signature (set after signing).
    /// 64 bytes: r (32 bytes) + s (32 bytes) for the BIP-340 Schnorr signature.
    #[serde(default)]
    pub sig_bytes: Vec<u8>,
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

/// Trait to extract an `IssueBundle` from the PCZT wire format with the correct
/// authorization type. Dispatches between [`Bundle::to_awaiting_sighash`] and
/// [`Bundle::to_signed`] based on the [`IssueAuth`] type parameter.
#[cfg(all(feature = "orchard", zcash_unstable = "nu7"))]
pub(crate) trait FromPcztIssue: orchard::issuance::IssueAuth + Sized {
    fn from_pczt_issue(wire: &Bundle) -> Option<orchard::issuance::IssueBundle<Self>>;
}

#[cfg(all(feature = "orchard", zcash_unstable = "nu7"))]
impl FromPcztIssue for orchard::issuance::AwaitingSighash {
    fn from_pczt_issue(wire: &Bundle) -> Option<orchard::issuance::IssueBundle<Self>> {
        wire.to_awaiting_sighash()
    }
}

#[cfg(all(feature = "orchard", zcash_unstable = "nu7"))]
impl FromPcztIssue for orchard::issuance::Signed {
    fn from_pczt_issue(wire: &Bundle) -> Option<orchard::issuance::IssueBundle<Self>> {
        wire.to_signed()
    }
}

#[cfg(all(test, feature = "orchard", zcash_unstable = "nu7"))]
mod tests {
    use super::*;

    #[test]
    fn issue_intent_roundtrip() {
        let mut bundle = Bundle::default();
        assert!(!bundle.is_initialized());
        assert!(!bundle.has_intents());

        let intent = IssueIntent {
            asset_desc_hash: [0xAA; 32],
            recipient: [0x42; 43],
            value: 1_000_000,
            first_issuance: true,
            finalize: false,
        };
        bundle.intents.push(intent);

        assert!(bundle.is_initialized());
        assert!(bundle.has_intents());
        assert!(bundle.actions.is_empty()); // actions still empty — only intents set
        // is_initialized() returns true because intents are non-empty
    }

    #[test]
    fn bundle_with_intents_is_initialized() {
        let mut bundle = Bundle::default();
        assert!(!bundle.is_initialized());

        bundle.intents.push(IssueIntent {
            asset_desc_hash: [0xBB; 32],
            recipient: [0x43; 43],
            value: 500_000,
            first_issuance: true,
            finalize: true,
        });

        assert!(bundle.is_initialized());
        assert!(bundle.has_intents());
    }

    #[test]
    fn merge_concatenates_intents() {
        let mut a = Bundle::default();
        a.ik = [0x01; 32];
        a.intents.push(IssueIntent {
            asset_desc_hash: [0x11; 32],
            recipient: [0x41; 43],
            value: 100,
            first_issuance: true,
            finalize: false,
        });

        let mut b = Bundle::default();
        b.ik = [0x01; 32];
        b.intents.push(IssueIntent {
            asset_desc_hash: [0x22; 32],
            recipient: [0x42; 43],
            value: 200,
            first_issuance: false,
            finalize: false,
        });

        let merged = a.merge(&b);
        assert_eq!(merged.intents.len(), 2);
        assert_eq!(merged.ik, [0x01; 32]);
    }

    #[test]
    fn intent_serialization_roundtrip() {
        let mut bundle = Bundle::default();
        bundle.ik = [0xAB; 32];
        bundle.intents.push(IssueIntent {
            asset_desc_hash: [0xCC; 32],
            recipient: [0x42; 43],
            value: 2_000_000,
            first_issuance: true,
            finalize: true,
        });

        // Serialize to bytes (postcard wire format)
        let bytes = postcard::to_allocvec(&bundle).expect("serialize");
        // Deserialize back
        let deserialized: Bundle = postcard::from_bytes(&bytes).expect("deserialize");

        assert_eq!(deserialized.ik, bundle.ik);
        assert_eq!(deserialized.intents.len(), 1);
        assert_eq!(deserialized.intents[0].asset_desc_hash, [0xCC; 32]);
        assert_eq!(deserialized.intents[0].value, 2_000_000);
        assert!(deserialized.intents[0].first_issuance);
        assert!(deserialized.intents[0].finalize);
        assert!(deserialized.actions.is_empty());
    }
}
