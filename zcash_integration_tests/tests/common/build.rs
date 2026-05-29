//! Transaction building helpers for integration tests.

use orchard::{
    flavor::OrchardZSA,
    keys::SpendAuthorizingKey,
    note::AssetBase,
    value::NoteValue,
    Address as OrchardAddress,
    Anchor,
};
use transparent::{
    address::TransparentAddress,
    builder::TransparentSigningSet,
};
use zcash_primitives::transaction::{
    builder::{BuildConfig, Builder, BuildResult},
    fees::zip317,
};
use zcash_protocol::{
    consensus::{BlockHeight, Parameters},
    memo::MemoBytes,
    value::Zatoshis,
};

/// Helper to parse a hex txid string into a `[u8; 32]` for [`OutPoint::new`].
/// The RPC txid is in display order (big-endian); we reverse it to internal order.
pub fn parse_txid(hex_str: &str) -> Result<[u8; 32], String> {
    let mut bytes = hex::decode(hex_str).map_err(|e| format!("hex decode txid: {e}"))?;
    let len = bytes.len();
    if len != 32 {
        return Err(format!("txid must be 32 bytes, got {len}"));
    }
    bytes.reverse();
    Ok(bytes.try_into().unwrap())
}

/// Builds a shielding transaction: transparent input → orchard output.
///
/// Returns the built result (transaction and metadata).
#[allow(clippy::too_many_arguments)]
pub fn build_shielding_tx(
    params: &impl Parameters,
    height: BlockHeight,
    pubkey: secp256k1::PublicKey,
    utxo: transparent::bundle::OutPoint,
    coin_value: Zatoshis,
    coin_script: transparent::address::Script,
    recipient: OrchardAddress,
    change_addr: TransparentAddress,
    ovk: Option<orchard::keys::OutgoingViewingKey>,
    orchard_sak: &SpendAuthorizingKey,
    orchard_anchor: Anchor,
    signing_set: &TransparentSigningSet,
) -> Result<BuildResult, String> {
    let mut builder = Builder::new(
        params,
        height,
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: Some(orchard_anchor),
        },
    );

    builder
        .add_transparent_p2pkh_input(
            pubkey,
            utxo,
            transparent::bundle::TxOut::new(coin_value, coin_script),
        )
        .map_err(|e| format!("add transparent input: {e}"))?;

    let zec_fee = 15_000u64;
    let change_amount = 35_000u64;
    let orchard_value = Zatoshis::from_u64(
        u64::from(coin_value).saturating_sub(zec_fee + change_amount),
    )
    .unwrap_or(Zatoshis::const_from_u64(1));

    builder
        .add_orchard_output::<zip317::FeeError>(
            ovk,
            recipient,
            orchard_value,
            AssetBase::zatoshi(),
            MemoBytes::empty(),
        )
        .map_err(|e| format!("add orchard output: {e}"))?;

    builder
        .add_transparent_output(&change_addr, Zatoshis::const_from_u64(change_amount))
        .map_err(|e| format!("add transparent change: {e}"))?;

    builder
        .mock_build(
            signing_set,
            &[],
            &[orchard_sak.clone()],
            |_| false,
            rand_core::OsRng,
        )
        .map_err(|e| format!("mock_build failed: {e}"))
}

/// Builds an issuance transaction for a custom asset.
///
/// Spends a ZEC orchard note to cover fees, issues a custom asset via the issue bundle.
#[allow(clippy::too_many_arguments)]
pub fn build_issuance_tx(
    params: &impl Parameters,
    height: BlockHeight,
    pubkey: secp256k1::PublicKey,
    utxo: transparent::bundle::OutPoint,
    coin_value: Zatoshis,
    coin_script: transparent::address::Script,
    change_addr: TransparentAddress,
    orchard_fvk: &orchard::keys::FullViewingKey,
    orchard_note: orchard::Note,
    merkle_path: orchard::tree::MerklePath,
    anchor: Anchor,
    isk: &orchard::issuance::auth::IssueAuthKey<orchard::issuance::auth::ZSASchnorr>,
    asset_desc_hash: [u8; 32],
    issue_recipient: OrchardAddress,
    issue_value: NoteValue,
    first_issuance: bool,
    zec_change_recipient: OrchardAddress,
    orchard_sak: &SpendAuthorizingKey,
    signing_set: &TransparentSigningSet,
    is_new_asset: impl Fn(&AssetBase) -> bool,
) -> Result<BuildResult, String> {
    let mut builder = Builder::new(
        params,
        height,
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: Some(anchor),
        },
    );

    builder
        .add_transparent_p2pkh_input(
            pubkey,
            utxo,
            transparent::bundle::TxOut::new(coin_value, coin_script),
        )
        .map_err(|e| format!("add transparent input: {e}"))?;

    builder
        .add_orchard_spend::<zip317::FeeError>(
            orchard_fvk.clone(),
            orchard_note,
            merkle_path,
        )
        .map_err(|e| format!("add orchard spend: {e}"))?;

    builder
        .add_issue_output::<zip317::FeeError>(
            isk,
            asset_desc_hash,
            issue_recipient,
            issue_value,
            first_issuance,
        )
        .map_err(|e| format!("add issue output: {e}"))?;

    let total_zec_in = u64::from(coin_value) + orchard_note.value().inner();
    let fee_margin = 525_000u64;
    let zec_out = Zatoshis::from_u64(total_zec_in.saturating_sub(fee_margin))
        .unwrap_or(Zatoshis::const_from_u64(1));

    builder
        .add_orchard_output::<zip317::FeeError>(
            Some(orchard_fvk.to_ovk(orchard::keys::Scope::External)),
            zec_change_recipient,
            zec_out,
            AssetBase::zatoshi(),
            MemoBytes::empty(),
        )
        .map_err(|e| format!("add orchard output: {e}"))?;

    builder
        .mock_build(
            signing_set,
            &[],
            &[orchard_sak.clone()],
            is_new_asset,
            rand_core::OsRng,
        )
        .map_err(|e| format!("mock_build failed: {e}"))
}

/// Serializes a transaction to hex for RPC broadcast.
pub fn tx_to_hex(tx: &zcash_primitives::transaction::Transaction) -> Result<String, String> {
    let mut raw = Vec::new();
    tx.write(&mut raw).map_err(|e| format!("tx write: {e}"))?;
    Ok(hex::encode(&raw))
}
