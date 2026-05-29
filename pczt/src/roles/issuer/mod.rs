//! The Issuer role (ZSA asset minter).
//!
//! Builds and signs the ZSA issuance bundle using the first orchard nullifier
//! from the PCZT (required for rho derivation per ZIP-227).
//!
//! Two-phase design:
//! - Phase 1 (after Creator): build IssueBundle<AwaitingSighash>, store in pczt.issue
//! - Phase 2 (after IoFinalizer): sign with the shielded sighash

use alloc::vec::Vec;
use rand_core::RngCore;

use orchard::{
    issuance::{
        IssueAuth, IssueBundle,
        auth::{IssueAuthKey, ZSASchnorr},
    },
    note::{ExtractedNoteCommitment, Nullifier},
};

use crate::Pczt;

pub struct Issuer {
    pczt: Pczt,
}

impl Issuer {
    /// Instantiates the Issuer role with the given PCZT.
    pub fn new(pczt: Pczt) -> Self {
        Self { pczt }
    }

    /// Phase 1: builds the issue bundle using the first orchard nullifier
    /// from the PCZT, derives rho values, and stores the unsigned
    /// `IssueBundle<AwaitingSighash>` in `pczt.issue`.
    ///
    /// Must run after Creator and before IoFinalizer.
    #[cfg(feature = "zcp-builder")]
    pub fn build_awaiting_sighash<R: RngCore>(
        self,
        zsa: zcash_primitives::transaction::zsa_builder::ZsaBuilder,
        rng: R,
    ) -> Result<Pczt, Error> {
        let first_nf = self
            .pczt
            .orchard()
            .actions()
            .first()
            .map(|action| Nullifier::from_bytes(action.spend().nullifier()))
            .and_then(|nf| nf.into_option())
            .ok_or(Error::NoOrchardActions)?;

        let (bundle, _ik) = zsa
            .build(&first_nf, rng)
            .ok_or(Error::ZsaNotInitialized)?;

        Ok(Pczt {
            issue: serialize_bundle(&bundle),
            ..self.pczt
        })
    }

    /// Phase 2: reads the unsigned issue bundle from `pczt.issue`, signs it
    /// with the given `sighash` and issuance key, and stores the signed
    /// `IssueBundle<Signed>` back.
    ///
    /// Must run after IoFinalizer (which computes the shielded sighash that
    /// covers the unsigned issue bundle).
    #[cfg(feature = "zcp-builder")]
    pub fn sign(
        self,
        isk: &IssueAuthKey<ZSASchnorr>,
        sighash: [u8; 32],
    ) -> Result<Pczt, Error> {
        // Reconstruct AwaitingSighash bundle from wire format
        let bundle = deserialize_bundle(&self.pczt.issue)
            .ok_or(Error::InvalidIssueData)?;

        let signed = bundle
            .prepare(sighash)
            .sign(isk)
            .map_err(Error::IssuanceSign)?;

        Ok(Pczt {
            issue: serialize_bundle(&signed),
            ..self.pczt
        })
    }

    /// Returns the PCZT without modifying the issue bundle.
    pub fn finish(self) -> Pczt {
        self.pczt
    }
}

/// Serializes any [`IssueBundle`] into the PCZT issue wire format.
fn serialize_bundle<T: IssueAuth>(bundle: &IssueBundle<T>) -> crate::issue::Bundle {
    let ik = bundle.ik().to_bytes();
    let actions = bundle
        .actions()
        .iter()
        .map(|action| {
            let notes: Vec<crate::issue::IssueNote> = action
                .notes()
                .iter()
                .map(|note| crate::issue::IssueNote {
                    recipient: note.recipient().to_raw_address_bytes(),
                    value: note.value().inner(),
                    asset: note.asset().to_bytes(),
                    rseed: *note.rseed().as_bytes(),
                    rho: note.rho().to_bytes(),
                    cmx: ExtractedNoteCommitment::from(note.commitment()).to_bytes(),
                    ephemeral_key: [0u8; 32],
                    enc_ciphertext: Vec::new(),
                    out_ciphertext: Vec::new(),
                })
                .collect();
            crate::issue::IssueAction {
                asset_desc_hash: *action.asset_desc_hash(),
                notes,
                flags: action.flags().to_byte(),
            }
        })
        .collect();
    crate::issue::Bundle { ik, actions }
}

/// Deserializes the PCZT issue wire format back into an `IssueBundle<AwaitingSighash>`.
fn deserialize_bundle(wire: &crate::issue::Bundle) -> Option<IssueBundle<orchard::issuance::AwaitingSighash>> {
    use orchard::{
        issuance::{IssueAction, IssueBundle, IssuanceFlags},
        note::{AssetBase, RandomSeed, Rho},
        Address, Note,
    };
    use nonempty::NonEmpty;

    if wire.actions.is_empty() {
        return None;
    }

    let ik = orchard::issuance::auth::IssueValidatingKey::<ZSASchnorr>::from_bytes(&wire.ik)?;

    let actions: Vec<IssueAction> = wire
        .actions
        .iter()
        .map(|a| {
            let notes: Vec<Note> = a
                .notes
                .iter()
                .map(|n| {
                    let recipient = Address::from_raw_address_bytes(&n.recipient).into_option()?;
                    let asset = AssetBase::from_bytes(&n.asset).into_option()?;
                    let rho = Rho::from_bytes(&n.rho).into_option()?;
                    let rseed = RandomSeed::from_bytes(n.rseed, &rho).into_option()?;
                    Note::from_parts(recipient, orchard::value::NoteValue::from_raw(n.value), asset, rho, rseed).into_option()
                })
                .collect::<Option<Vec<_>>>()?;
            let flags = IssuanceFlags::from_byte(a.flags)?;
            Some(IssueAction::from_parts(a.asset_desc_hash, notes, flags.finalize()))
        })
        .collect::<Option<Vec<_>>>()?;

    let actions = NonEmpty::from_vec(actions)?;
    Some(IssueBundle::from_parts(ik, actions, orchard::issuance::AwaitingSighash))
}

/// Errors that can occur during issuance.
#[derive(Debug)]
pub enum Error {
    /// The PCZT has no orchard actions — cannot derive the first nullifier
    /// required for rho derivation (ZIP-227).
    NoOrchardActions,
    /// The ZSA builder was not initialized (no issuance outputs added).
    ZsaNotInitialized,
    /// The data stored in `pczt.issue` could not be deserialized.
    InvalidIssueData,
    /// Failed to sign the issuance bundle.
    IssuanceSign(orchard::issuance::Error),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::NoOrchardActions => write!(f, "PCZT has no orchard actions"),
            Error::ZsaNotInitialized => write!(f, "ZSA builder is not initialized"),
            Error::InvalidIssueData => write!(f, "pczt.issue contains invalid data"),
            Error::IssuanceSign(e) => write!(f, "Issuance signing error: {e}"),
        }
    }
}

impl core::error::Error for Error {}
