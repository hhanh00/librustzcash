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
    value::NoteValue,
    Address,
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
        let first_nf = first_orchard_nullifier(&self.pczt)?;
        build_with_zsa(self.pczt, zsa, &first_nf, rng)
    }

    /// Phase 1 (intent-based): builds the issue bundle from issuance intents
    /// stored in the PCZT wire format.
    ///
    /// Reads [`crate::issue::Bundle::intents`] and [`crate::issue::Bundle::ik`]
    /// from the PCZT, constructs a [`ZsaBuilder`] from the provided issuance
    /// signing key, processes each intent, then derives rho values from the
    /// first Orchard nullifier (ZIP-227) and stores the unsigned
    /// `IssueBundle<AwaitingSighash>` in `pczt.issue.actions`.
    ///
    /// After a successful build, the intents are cleared and the bundle is
    /// serialized into the actions field.
    ///
    /// Must run after Creator and before IoFinalizer.
    ///
    /// [`ZsaBuilder`]: zcash_primitives::transaction::zsa_builder::ZsaBuilder
    #[cfg(feature = "zcp-builder")]
    pub fn build_awaiting_sighash_from_intents<R: RngCore>(
        mut self,
        isk: &IssueAuthKey<ZSASchnorr>,
        mut rng: R,
    ) -> Result<Pczt, Error> {
        let intents = core::mem::take(&mut self.pczt.issue.intents);
        if intents.is_empty() {
            return Err(Error::NoIssuanceIntents);
        }
        if !self.pczt.issue.actions.is_empty() {
            return Err(Error::AlreadyBuilt);
        }

        // Build the ZsaBuilder from intents.
        let mut zsa =
            zcash_primitives::transaction::zsa_builder::ZsaBuilder::new(isk.clone());

        for intent in &intents {
            let recipient = Address::from_raw_address_bytes(&intent.recipient)
                .into_option()
                .ok_or(Error::InvalidRecipient)?;
            let value = NoteValue::from_raw(intent.value);

            if intent.value > 0 || intent.first_issuance {
                zsa.add_issue_output(
                    intent.asset_desc_hash,
                    recipient,
                    value,
                    intent.first_issuance,
                    &mut rng,
                )
                .map_err(|_| Error::IssuanceBuild)?;
            }

            if intent.finalize {
                zsa.finalize_asset(&intent.asset_desc_hash)
                    .map_err(|_| Error::IssuanceBuild)?;
            }
        }

        let first_nf = first_orchard_nullifier(&self.pczt)?;
        build_with_zsa(self.pczt, zsa, &first_nf, rng)
    }

    /// Phase 2: reads the unsigned issue bundle from `pczt.issue`, signs it
    /// using the shielded sighash (stored by the IoFinalizer) and the given
    /// issuance key, and stores the signed `IssueBundle<Signed>` back.
    ///
    /// Must run after IoFinalizer (which computes the shielded sighash that
    /// covers the unsigned issue bundle and stores it on the PCZT).
    #[cfg(feature = "zcp-builder")]
    pub fn sign(
        self,
        isk: &IssueAuthKey<ZSASchnorr>,
    ) -> Result<Pczt, Error> {
        // Reconstruct AwaitingSighash bundle from wire format
        let bundle = deserialize_bundle(&self.pczt.issue)
            .ok_or(Error::InvalidIssueData)?;

        let sighash = (*self.pczt.shielded_sighash())
            .ok_or(Error::MissingSighash)?;

        let signed = bundle
            .prepare(sighash)
            .sign(isk)
            .map_err(Error::IssuanceSign)?;

        Ok(Pczt {
            issue: serialize_signed_bundle(&signed),
            ..self.pczt
        })
    }

    /// Returns the PCZT without modifying the issue bundle.
    pub fn finish(self) -> Pczt {
        self.pczt
    }
}

/// Extracts the first Orchard nullifier from the PCZT's Orchard bundle.
///
/// Required for rho derivation per ZIP-227.
#[cfg(feature = "zcp-builder")]
fn first_orchard_nullifier(pczt: &Pczt) -> Result<Nullifier, Error> {
    pczt.orchard()
        .actions()
        .first()
        .map(|action| Nullifier::from_bytes(action.spend().nullifier()))
        .and_then(|nf| nf.into_option())
        .ok_or(Error::NoOrchardActions)
}

/// Shared helper: consumes a populated [`ZsaBuilder`] using the first Orchard
/// nullifier, serializes the resulting bundle, clears intents, and returns the
/// updated PCZT.
#[cfg(feature = "zcp-builder")]
fn build_with_zsa<R: RngCore>(
    mut pczt: Pczt,
    zsa: zcash_primitives::transaction::zsa_builder::ZsaBuilder,
    first_nullifier: &Nullifier,
    rng: R,
) -> Result<Pczt, Error> {
    let (bundle, _ik) = zsa
        .build(first_nullifier, rng)
        .ok_or(Error::ZsaNotInitialized)?;

    // Clear intents since we've built the bundle from them.
    pczt.issue.intents.clear();

    Ok(Pczt {
        issue: serialize_bundle(&bundle),
        ..pczt
    })
}

/// Serializes any [`IssueBundle`] into the PCZT issue wire format.
fn serialize_bundle<T: IssueAuth>(bundle: &IssueBundle<T>) -> crate::issue::Bundle {
    serialize_bundle_inner(bundle, &[])
}

/// Serializes a signed [`IssueBundle`] into the PCZT issue wire format,
/// including the issuance authorization signature.
fn serialize_signed_bundle(bundle: &IssueBundle<orchard::issuance::Signed>) -> crate::issue::Bundle {
    let sig_bytes = bundle.authorization().signature().sig().encode();
    serialize_bundle_inner(bundle, &sig_bytes)
}

fn serialize_bundle_inner<T: IssueAuth>(
    bundle: &IssueBundle<T>,
    sig_bytes: &[u8],
) -> crate::issue::Bundle {
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
                sig_bytes: sig_bytes.to_vec(),
            }
        })
        .collect();
    crate::issue::Bundle { ik, actions, ..Default::default() }
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
    /// The shielded sighash has not been stored on the PCZT.
    /// The [`IoFinalizer`](crate::roles::io_finalizer::IoFinalizer) must
    /// run before the Issuer's sign phase.
    MissingSighash,
    /// Failed to sign the issuance bundle.
    IssuanceSign(orchard::issuance::Error),
    /// No issuance intents to build from.
    NoIssuanceIntents,
    /// Cannot build from intents when actions already exist in the PCZT.
    AlreadyBuilt,
    /// A recipient address in an issuance intent is invalid.
    InvalidRecipient,
    /// Failed to build the issuance bundle from intents.
    IssuanceBuild,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::NoOrchardActions => write!(f, "PCZT has no orchard actions"),
            Error::ZsaNotInitialized => write!(f, "ZSA builder is not initialized"),
            Error::InvalidIssueData => write!(f, "pczt.issue contains invalid data"),
            Error::MissingSighash => write!(f, "shielded sighash not set — IoFinalizer must run before sign"),
            Error::IssuanceSign(e) => write!(f, "Issuance signing error: {e}"),
            Error::NoIssuanceIntents => write!(f, "no issuance intents to build from"),
            Error::AlreadyBuilt => write!(f, "cannot build from intents when actions already exist"),
            Error::InvalidRecipient => write!(f, "invalid recipient address in issuance intent"),
            Error::IssuanceBuild => write!(f, "failed to build issuance bundle from intents"),
        }
    }
}

impl core::error::Error for Error {}
