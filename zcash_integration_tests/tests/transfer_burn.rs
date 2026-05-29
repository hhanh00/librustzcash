//! Integration test: ZSA transfer and burn.
//!
//! Tests the add_burn API: burn custom assets is accepted, burn zatoshi is rejected.
//! Then builds and broadcasts a full issuance+burn transaction.
//!
//! Requires a running zebra node with NU7 support in regtest mode.

use nonempty::NonEmpty;
use orchard::{
    issuance::auth::{IssueAuthKey, IssueValidatingKey},
    issuance::compute_asset_desc_hash,
    note::{AssetBase, AssetId},
    value::NoteValue,
};
use transparent::builder::TransparentSigningSet;
use zcash_primitives::transaction::{
    builder::{BuildConfig, Builder},
    fees::zip317,
    Transaction,
};
use zcash_protocol::consensus::{BlockHeight, BranchId, Parameters};
use zcash_protocol::local_consensus::LocalNetwork;
use zcash_protocol::memo::MemoBytes;
use zcash_protocol::value::Zatoshis;

mod common;

use common::build::{build_shielding_tx, parse_txid, tx_to_hex};
use common::keys::{encode_transparent_address, make_orchard_account, make_transparent_account, orchard_sak};
use common::rpc::RpcClient;
use common::tree::OrchardTreeState;

fn params() -> LocalNetwork {
    LocalNetwork {
        overwinter: Some(BlockHeight::from_u32(1)),
        sapling: Some(BlockHeight::from_u32(1)),
        blossom: Some(BlockHeight::from_u32(1)),
        heartwood: Some(BlockHeight::from_u32(1)),
        canopy: Some(BlockHeight::from_u32(1)),
        nu5: Some(BlockHeight::from_u32(1)),
        nu6: Some(BlockHeight::from_u32(1)),
        nu6_1: Some(BlockHeight::from_u32(1)),
        nu7: Some(BlockHeight::from_u32(1)),
    }
}

/// Helper that builds and broadcasts a shielding tx, returns (note, merkle_path, anchor, tree).
fn setup_shielding_note(
    rpc: &RpcClient,
    taddr: &transparent::address::TransparentAddress,
    taddr_str: &str,
    t_sk: &secp256k1::SecretKey,
    signing_set: &TransparentSigningSet,
    orchard_fvk: &orchard::keys::FullViewingKey,
    orchard_addr: orchard::Address,
    orch_sak: &orchard::keys::SpendAuthorizingKey,
) -> (
    orchard::Note,
    orchard::tree::MerklePath,
    orchard::Anchor,
    OrchardTreeState,
) {
    let params = params();
    let utxos = rpc.list_unspent(&[taddr_str.to_string()]).expect("listunspent");
    let utxo = &utxos[0];
    let txid: String = utxo["txid"].as_str().expect("txid").to_string();
    let vout: u32 = utxo["vout"].as_u64().expect("vout") as u32;
    let amount: u64 = (utxo["amount"].as_f64().expect("amount") * 100_000_000.0) as u64;

    let secp = secp256k1::Secp256k1::signing_only();
    let t_pubkey = t_sk.public_key(&secp);
    let outpoint_hash = parse_txid(&txid).expect("parse txid");
    let outpoint = transparent::bundle::OutPoint::new(outpoint_hash, vout);
    let coin_value = Zatoshis::from_u64(amount).expect("valid amount");
    let coin_script: transparent::address::Script = taddr.script().into();

    let result = build_shielding_tx(
        &params,
        BlockHeight::from_u32(101),
        t_pubkey,
        outpoint,
        coin_value,
        coin_script,
        orchard_addr,
        *taddr,
        Some(orchard_fvk.to_ovk(orchard::keys::Scope::External)),
        orch_sak,
        orchard::Anchor::empty_tree(),
        signing_set,
    )
    .expect("build shielding tx");

    let shield_tx = result.into_transaction();
    let shield_hex = tx_to_hex(&shield_tx).expect("serialize");

    let shield_txid = rpc
        .send_raw_transaction(&shield_hex)
        .expect("sendrawtransaction shield");

    let shield_block_hash = rpc
        .wait_for_confirmation(&shield_txid)
        .expect("shield confirmed");

    let mut tree = OrchardTreeState::new();
    let sync = tree.sync_block(rpc, &shield_block_hash, &params).expect("sync");

    let ob = shield_tx.orchard_bundle().expect("orchard bundle");
    let actions = ob.as_zsa_bundle().actions();

    use orchard::primitives::OrchardDomain;
    use zcash_note_encryption::try_note_decryption;
    let (note, _, _) = try_note_decryption(
        &OrchardDomain::for_action(&actions[0]),
        &orchard_fvk.to_ivk(orchard::keys::Scope::External).prepare(),
        &actions[0],
    )
    .expect("decrypt note");

    let note_index = sync.count_before;
    let anchor = tree.anchor();
    let merkle_path = tree.witness(note_index);

    (note, merkle_path, anchor, tree)
}

#[test]
#[cfg(zcash_unstable = "nu7")]
fn test_burn_custom_asset() {
    let params = params();
    let rpc = RpcClient::new();

    // Verify regtest chain
    let info = rpc.get_blockchain_info().expect("getblockchaininfo");
    assert_eq!(
        info["chain"].as_str().expect("chain"),
        "regtest",
        "Test requires regtest chain"
    );

    // Generate keys
    let (_tsk, taddr, t_sk) = make_transparent_account(b"zsa_burn_test_seed01");
    let taddr_str = encode_transparent_address(
        &taddr,
        zcash_protocol::consensus::NetworkType::Regtest,
    );
    let (orchard_sk, orchard_fvk, orchard_addr) =
        make_orchard_account(&[0x02; 32]);
    let orch_sak = orchard_sak(&orchard_sk);
    let isk = IssueAuthKey::<orchard::issuance::auth::ZSASchnorr>::from_zip32_seed(
        b"zsa_burn_issue_sd01",
        1,
        0,
    )
    .expect("issue auth key");
    let ik = IssueValidatingKey::from(&isk);

    // Fund
    let _ = rpc
        .generate_to_address(101, &taddr_str)
        .expect("generatetoaddress");

    let secp = secp256k1::Secp256k1::signing_only();
    let t_pubkey = t_sk.public_key(&secp);

    let mut signing_set = TransparentSigningSet::new();
    signing_set.add_key(t_sk);

    // Get UTXO details for builder API tests
    let utxos = rpc
        .list_unspent(&[taddr_str.clone()])
        .expect("listunspent");
    let utxo = &utxos[0];
    let txid: String = utxo["txid"].as_str().expect("txid").to_string();
    let vout: u32 = utxo["vout"].as_u64().expect("vout") as u32;
    let amount: u64 = (utxo["amount"].as_f64().expect("amount") * 100_000_000.0) as u64;
    let outpoint_hash = parse_txid(&txid).expect("parse txid");
    let outpoint = transparent::bundle::OutPoint::new(outpoint_hash, vout);
    let coin_value = Zatoshis::from_u64(amount).expect("valid amount");
    let coin_script: transparent::address::Script = taddr.script().into();

    let desc_hash = compute_asset_desc_hash(&NonEmpty::from_slice(b"BURNABLE").unwrap());

    // ── Test 1: add_burn accepts custom assets ──
    {
        let custom_asset = AssetBase::custom(&AssetId::new_v0(&ik, &desc_hash));

        let mut builder = Builder::new(
            &params,
            BlockHeight::from_u32(102),
            BuildConfig::Standard {
                sapling_anchor: None,
                orchard_anchor: Some(orchard::Anchor::empty_tree()),
            },
        );
        builder
            .add_transparent_p2pkh_input(t_pubkey, outpoint.clone(), transparent::bundle::TxOut::new(coin_value, coin_script.clone()))
            .expect("transparent input");

        let result = builder.add_burn::<zip317::FeeError>(100, custom_asset);
        assert!(
            result.is_ok(),
            "add_burn should accept custom asset, got: {result:?}"
        );
        println!("PASS: add_burn accepts custom assets");
    }

    // ── Test 2: add_burn rejects zatoshi ──
    {
        let mut builder = Builder::new(
            &params,
            BlockHeight::from_u32(102),
            BuildConfig::Standard {
                sapling_anchor: None,
                orchard_anchor: Some(orchard::Anchor::empty_tree()),
            },
        );
        builder
            .add_transparent_p2pkh_input(t_pubkey, outpoint.clone(), transparent::bundle::TxOut::new(coin_value, coin_script.clone()))
            .expect("transparent input");

        let result = builder.add_burn::<zip317::FeeError>(100, AssetBase::zatoshi());
        assert!(
            result.is_err(),
            "add_burn should reject zatoshi"
        );
        println!("PASS: add_burn rejects zatoshi");
    }

    // ── Test 3: Build and broadcast an issuance+burn tx ──
    // First create a shielding tx to get an orchard note
    let (orchard_note, merkle_path, anchor, _tree) = setup_shielding_note(
        &rpc, &taddr, &taddr_str, &t_sk, &signing_set,
        &orchard_fvk, orchard_addr, &orch_sak,
    );

    // Get a new UTXO for the issuance+burn tx
    let utxos2 = rpc
        .list_unspent(&[taddr_str.clone()])
        .expect("listunspent");
    let utxo2 = &utxos2[0];
    let txid2: String = utxo2["txid"].as_str().expect("txid").to_string();
    let vout2: u32 = utxo2["vout"].as_u64().expect("vout") as u32;
    let amount2: u64 = (utxo2["amount"].as_f64().expect("amount") * 100_000_000.0) as u64;
    let outpoint_hash2 = parse_txid(&txid2).expect("parse txid2");
    let outpoint2 = transparent::bundle::OutPoint::new(outpoint_hash2, vout2);
    let coin_value2 = Zatoshis::from_u64(amount2).expect("valid amount");
    let coin_script2: transparent::address::Script = taddr.script().into();

    let current_height = BlockHeight::from_u32(102);
    let burn_asset = AssetBase::custom(&AssetId::new_v0(&ik, &desc_hash));

    let mut builder = Builder::new(
        &params,
        current_height,
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: Some(anchor),
        },
    );

    builder
        .add_transparent_p2pkh_input(t_pubkey, outpoint2, transparent::bundle::TxOut::new(coin_value2, coin_script2))
        .expect("transparent input");

    builder
        .add_orchard_spend::<zip317::FeeError>(
            orchard_fvk.clone(),
            orchard_note,
            merkle_path,
        )
        .expect("orchard spend");

    builder
        .add_issue_output::<zip317::FeeError>(
            &isk,
            desc_hash,
            orchard_addr,
            NoteValue::from_raw(1_000_000),
            true,
        )
        .expect("issue output");

    builder
        .add_burn::<zip317::FeeError>(100_000, burn_asset)
        .expect("add burn");

    let zec_out = Zatoshis::from_u64(
        amount2.saturating_sub(500_000),
    )
    .unwrap_or(Zatoshis::const_from_u64(1));

    builder
        .add_orchard_output::<zip317::FeeError>(
            Some(orchard_fvk.to_ovk(orchard::keys::Scope::External)),
            orchard_addr,
            zec_out,
            AssetBase::zatoshi(),
            MemoBytes::empty(),
        )
        .expect("orchard output");

    builder
        .add_transparent_output(&taddr, Zatoshis::const_from_u64(5_000))
        .expect("transparent change");

    let result = builder
        .mock_build(
            &signing_set,
            &[],
            &[orch_sak.clone()],
            |_| true,
            rand_core::OsRng,
        )
        .expect("build issuance+burn tx");

    let burn_tx = result.into_transaction();
    let burn_hex = tx_to_hex(&burn_tx).expect("serialize");

    println!("Broadcasting issuance+burn tx...");
    let burn_txid = rpc
        .send_raw_transaction(&burn_hex)
        .expect("sendrawtransaction burn");

    let burn_block_hash = rpc
        .wait_for_confirmation(&burn_txid)
        .expect("burn tx confirmed");

    // Verify on-chain
    let raw_hex = rpc
        .get_raw_transaction(&burn_txid)
        .expect("getrawtransaction");
    let raw_bytes = hex::decode(&raw_hex).expect("hex decode");
    let on_chain_tx = Transaction::read(
        &raw_bytes[..],
        BranchId::for_height(&&params, current_height),
    )
    .expect("parse on-chain tx");

    let ob = on_chain_tx.orchard_bundle().expect("orchard bundle");
    let zsa_bundle = ob.as_zsa_bundle();
    assert!(
        !zsa_bundle.burn().is_empty(),
        "Expected non-empty burn in orchard bundle"
    );
    assert!(
        on_chain_tx.issue_bundle().is_some(),
        "Expected issue bundle"
    );

    println!(
        "SUCCESS: issuance+burn tx confirmed, burn={:?}, issue_actions={}",
        zsa_bundle.burn().len(),
        on_chain_tx.issue_bundle().unwrap().actions().len()
    );

    // Sync the block to keep tests independent
    let mut final_tree = OrchardTreeState::new();
    final_tree
        .sync_block(&rpc, &burn_block_hash, &params)
        .expect("final sync");
}
