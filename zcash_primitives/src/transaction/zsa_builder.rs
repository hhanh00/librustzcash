//! A builder for ZSA (Zcash Shielded Assets) issuance bundles.
//!
//! `ZsaBuilder` follows the same sub-builder delegation pattern used by
//! [`TransparentBuilder`], [`sapling::builder::Builder`], and [`orchard::builder::Builder`].
//! It wraps the issuance signing key and the partially-built [`IssueBundle`],
//! providing a wallet-facing API for asset issuance, multi-asset minting, and finalization.

use orchard::{
    Address,
    issuance,
    issuance::auth::{IssueAuthKey, IssueValidatingKey, ZSASchnorr},
    issuance::{AwaitingNullifier, AwaitingSighash, IssueBundle, IssueInfo},
    note::{AssetBase, Nullifier},
    value::NoteValue,
};
use rand_core::RngCore;

/// A builder for constructing a ZSA issuance bundle.
///
/// Create with [`ZsaBuilder::new`], add issuance outputs with
/// [`add_issue_output`](ZsaBuilder::add_issue_output), optionally finalize
/// assets with [`finalize_asset`](ZsaBuilder::finalize_asset), then hand
/// the builder to [`Builder::set_zsa_builder`] or retrieve it via
/// [`Builder::zsa_builder`].
///
/// The cross-bundle dependency (ZIP-227: issuance notes need the first Orchard
/// nullifier for rho derivation) is handled automatically inside
/// [`Builder::build`] — the wallet does not need to add dummy Orchard actions.
#[derive(Debug)]
pub struct ZsaBuilder {
    ik: IssueAuthKey<ZSASchnorr>,
    bundle: Option<IssueBundle<AwaitingNullifier>>,
}

impl ZsaBuilder {
    /// Creates a new [`ZsaBuilder`] with the given issuance key.
    ///
    /// The key is derived from the wallet seed via ZIP-32:
    /// `IssueAuthKey::from_zip32_seed(seed, coin_type, account)`.
    ///
    /// The bundle is not initialized until the first call to
    /// [`add_issue_output`](Self::add_issue_output).
    pub fn new(ik: IssueAuthKey<ZSASchnorr>) -> Self {
        ZsaBuilder {
            ik,
            bundle: None,
        }
    }

    /// Adds an issuance output for the given asset.
    ///
    /// On the first call, this initializes the internal [`IssueBundle`]. On
    /// subsequent calls:
    /// - If `asset_desc_hash` matches an existing action, the notes are
    ///   appended to that action.
    /// - If `asset_desc_hash` is new, a new [`IssueAction`] is created.
    ///
    /// If `first_issuance` is true, a zero-value reference note is prepended
    /// (required by consensus for the first issuance of an asset). Passing
    /// `first_issuance = true` for an already-seen `asset_desc_hash` returns
    /// an error.
    ///
    /// Returns the [`AssetBase`] of the issued asset.
    pub fn add_issue_output(
        &mut self,
        asset_desc_hash: [u8; 32],
        recipient: Address,
        value: NoteValue,
        first_issuance: bool,
        rng: impl RngCore,
    ) -> Result<AssetBase, issuance::Error> {
        match self.bundle.as_mut() {
            Some(bundle) => {
                bundle.add_recipient(asset_desc_hash, recipient, value, first_issuance, rng)
            }
            None => {
                let (bundle, asset) = IssueBundle::new(
                    IssueValidatingKey::from(&self.ik),
                    asset_desc_hash,
                    Some(IssueInfo { recipient, value }),
                    first_issuance,
                    rng,
                );
                self.bundle = Some(bundle);
                Ok(asset)
            }
        }
    }

    /// Marks an asset as finalized, preventing further issuance of that asset
    /// type.
    ///
    /// Returns an error if the bundle has not been initialized or if no action
    /// matches the given `asset_desc_hash`.
    pub fn finalize_asset(&mut self, asset_desc_hash: &[u8; 32]) -> Result<(), issuance::Error> {
        self.bundle
            .as_mut()
            .ok_or(issuance::Error::IssueActionNotFound)?
            .finalize_action(asset_desc_hash)
    }

    /// Returns `true` if the issuance bundle has been initialized (i.e. at
    /// least one call to [`add_issue_output`](Self::add_issue_output)).
    pub fn is_initialized(&self) -> bool {
        self.bundle.is_some()
    }

    /// Returns a reference to the issuance key.
    pub fn issuance_key(&self) -> &IssueAuthKey<ZSASchnorr> {
        &self.ik
    }

    /// Returns a reference to the internal bundle, if initialized.
    pub fn bundle(&self) -> Option<&IssueBundle<AwaitingNullifier>> {
        self.bundle.as_ref()
    }

    /// Consumes the builder and transitions the bundle from
    /// [`AwaitingNullifier`] to [`AwaitingSighash`] using the first Orchard
    /// nullifier (ZIP-227 rho derivation).
    ///
    /// Returns `None` if the bundle was never initialized.
    ///
    /// Called internally by the transaction [`Builder`] during
    /// [`build`](super::Builder::build).
    pub fn build(
        self,
        first_nullifier: &Nullifier,
        rng: impl RngCore,
    ) -> Option<(IssueBundle<AwaitingSighash>, IssueAuthKey<ZSASchnorr>)> {
        self.bundle
            .map(|b| (b.update_rho(first_nullifier, rng), self.ik))
    }
}
