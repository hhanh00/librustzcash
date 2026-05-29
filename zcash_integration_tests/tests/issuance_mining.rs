//! Integration test: ZSA issuance and mining.
//!
//! Tests the full lifecycle: fund → shield → issue → mine → verify on-chain.
//!
//! Requires a running zebra node with NU7 support in regtest mode.

use nonempty::NonEmpty;
use orchard::{
    issuance::auth::IssueAuthKey,
    issuance::compute_asset_desc_hash,
    note::AssetBase,
    value::NoteValue,
};
use transparent::builder::TransparentSigningSet;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, BranchId, Parameters};
use zcash_protocol::local_consensus::LocalNetwork;

mod common;

use common::build::{build_issuance_tx, build_shielding_tx, parse_txid, tx_to_hex};
use common::keys::{encode_transparent_address, make_orchard_account, make_transparent_account, orchard_sak};
use common::rpc::RpcClient;
use common::tree::OrchardTreeState;

#[test]
#[cfg(zcash_unstable = "nu7")]
fn test_issuance_and_mining() {
    let rpc = RpcClient::new();

    // 1. Verify we're connected to a regtest chain
    let info = rpc.get_blockchain_info().expect("getblockchaininfo");
    let chain = info["chain"].as_str().expect("chain field");
    assert!(
        chain == "regtest" || chain == "test",
        "This test requires a regtest chain, got: {chain}"
    );
    println!("Connected to {chain} chain");

    let params = LocalNetwork {
        overwinter: Some(BlockHeight::from_u32(1)),
        sapling: Some(BlockHeight::from_u32(1)),
        blossom: Some(BlockHeight::from_u32(1)),
        heartwood: Some(BlockHeight::from_u32(1)),
        canopy: Some(BlockHeight::from_u32(1)),
        nu5: Some(BlockHeight::from_u32(1)),
        nu6: Some(BlockHeight::from_u32(1)),
        nu6_1: Some(BlockHeight::from_u32(1)),
        nu7: Some(BlockHeight::from_u32(1)),
    };

    // 2. Generate keys
    let (_tsk, taddr, t_sk) = make_transparent_account(b"0123456789ABCDEF0123456789ABCDEF");
    let taddr_str = encode_transparent_address(
        &taddr,
        zcash_protocol::consensus::NetworkType::Regtest,
    );
    println!("Transparent address: {taddr_str}");
    let (orchard_sk, orchard_fvk, orchard_addr) =
        make_orchard_account(&[0x01; 32]);
    let orch_sak = orchard_sak(&orchard_sk);
    let isk = IssueAuthKey::<orchard::issuance::auth::ZSASchnorr>::from_zip32_seed(
        b"zsa_int_issue_seed01",
        1,
        0,
    )
    .expect("issue auth key");

    // 3. Mine blocks to get mature transparent funds
    println!("Generating 101 blocks...");
    let _block_hashes = rpc
        .generate(101)
        .expect("generate");
    println!("Done generating blocks");

    // 4. Get current height and a UTXO
    let info_after = rpc.get_blockchain_info().expect("getblockchaininfo after generate");
    let current_height = info_after["blocks"].as_u64().expect("blocks") as u32;
    println!("Current chain height: {current_height}");

    let utxos = rpc
        .get_address_utxos(&taddr_str)
        .expect("getaddressutxos");
    assert!(!utxos.is_empty(), "No UTXOs after generating blocks");
    let utxo = &utxos[0];
    let txid: String = utxo["txid"].as_str().expect("txid").to_string();
    let vout: u32 = utxo["outputIndex"].as_u64().expect("outputIndex") as u32;
    let amount: u64 = utxo["satoshis"].as_u64().expect("satoshis");

    println!("UTXO: {txid}:{vout} = {amount} zatoshis");

    // 5. Build the shielding transaction
    let secp = secp256k1::Secp256k1::signing_only();
    let t_pubkey = t_sk.public_key(&secp);
    let outpoint_hash = parse_txid(&txid).expect("parse txid");
    let outpoint = transparent::bundle::OutPoint::new(outpoint_hash, vout);
    let coin_value = zcash_protocol::value::Zatoshis::from_u64(amount).expect("valid amount");
    let coin_script: transparent::address::Script = taddr.script().into();

    let mut signing_set = TransparentSigningSet::new();
    signing_set.add_key(t_sk);

    let result = build_shielding_tx(
        &params,
        BlockHeight::from_u32(current_height + 1),
        t_pubkey,
        outpoint,
        coin_value,
        coin_script,
        orchard_addr,
        taddr,
        Some(orchard_fvk.to_ovk(orchard::keys::Scope::External)),
        &orch_sak,
        orchard::Anchor::empty_tree(),
        &signing_set,
    )
    .expect("build shielding tx");

    let shield_tx = result.into_transaction();
    let shield_hex = tx_to_hex(&shield_tx).expect("serialize shielding tx");

    // 6. Broadcast
    println!("Broadcasting shielding tx...");
    let shield_txid = rpc
        .send_raw_transaction(&shield_hex)
        .expect("sendrawtransaction");
    println!("Shielding txid: {shield_txid}");

    // Mine a block to confirm
    rpc.generate(1).expect("generate after shield");

    // 7. Wait for confirmation
    let shield_block_hash = rpc
        .wait_for_confirmation(&shield_txid)
        .expect("shielding tx confirmed");
    println!("Shielding tx confirmed in block: {shield_block_hash}");

    // 8. Sync the orchard commitment tree from the mined block
    let mut tree = OrchardTreeState::new();
    let sync = tree
        .sync_block(&rpc, &shield_block_hash, &params)
        .expect("sync block");
    println!(
        "Synced block {}: {} orchard commit(s) added",
        sync.height, sync.total_commitments
    );
    assert!(
        sync.total_commitments >= 1,
        "Expected at least 1 orchard commitment in shielding block"
    );

    // Decrypt our note from the shielding tx
    let orchard_bundle = shield_tx
        .orchard_bundle()
        .expect("shielding tx has orchard bundle");
    let zsa = orchard_bundle.as_zsa_bundle();
    let actions = zsa.actions();
    assert!(!actions.is_empty(), "Orchard bundle has actions");

    // Decrypt the note we created using the bundle's built-in batch
    // decryption, which handles ZSA-sized ciphertexts correctly
    let ivk = orchard_fvk.to_ivk(orchard::keys::Scope::External);
    let decrypted = zsa.decrypt_outputs_with_keys(&[ivk]);
    let (note_idx, _, orchard_note, _, _) = decrypted
        .into_iter()
        .next()
        .expect("decrypt orchard note");

    // Position of our note in the tree: count_before + action index
    let note_index = sync.count_before + note_idx;
    let anchor = tree.anchor();
    let merkle_path = tree.witness(note_index);
    println!("note_index={}", note_index);

    // 9. Build the issuance transaction
    let desc_hash = compute_asset_desc_hash(&NonEmpty::from_slice(b"WETH").unwrap());

    // Get another UTXO for the fee (the previous one was spent)
    let utxos2 = rpc
        .get_address_utxos(&taddr_str)
        .expect("getaddressutxos after shielding");
    let utxo2 = &utxos2[0];
    let txid2: String = utxo2["txid"].as_str().expect("txid").to_string();
    let vout2: u32 = utxo2["outputIndex"].as_u64().expect("outputIndex") as u32;
    let amount2: u64 = utxo2["satoshis"].as_u64().expect("satoshis");
    let outpoint_hash2 = parse_txid(&txid2).expect("parse txid2");
    let outpoint2 = transparent::bundle::OutPoint::new(outpoint_hash2, vout2);
    let coin_value2 = zcash_protocol::value::Zatoshis::from_u64(amount2).expect("valid amount");
    let coin_script2: transparent::address::Script = taddr.script().into();

    println!("Issuance UTXO: {txid2}:{vout2} = {amount2} zatoshis");

    let iss_result = build_issuance_tx(
        &params,
        BlockHeight::from_u32(sync.height + 1),
        t_pubkey,
        outpoint2,
        coin_value2,
        coin_script2,
        taddr,
        &orchard_fvk,
        orchard_note,
        merkle_path,
        anchor,
        &isk,
        desc_hash,
        orchard_addr,
        NoteValue::from_raw(1_000_000),
        true,
        orchard_addr,
        &orch_sak,
        &signing_set,
        |_| true,
    )
    .expect("build issuance tx");

    let iss_tx = iss_result.into_transaction();
    let iss_hex = tx_to_hex(&iss_tx).expect("serialize issuance tx");

    // 10. Broadcast issuance tx
    println!("Broadcasting issuance tx...");
    let iss_txid = rpc
        .send_raw_transaction(&iss_hex)
        .expect("sendrawtransaction issuance");
    println!("Issuance txid: {iss_txid}");

    // Mine a block to confirm
    rpc.generate(1).expect("generate after issuance");

    // 11. Wait for confirmation
    let iss_block_hash = rpc
        .wait_for_confirmation(&iss_txid)
        .expect("issuance tx confirmed");
    println!("Issuance tx confirmed in block: {iss_block_hash}");

    // 12. Sync the block
    let sync2 = tree
        .sync_block(&rpc, &iss_block_hash, &params)
        .expect("sync issuance block");

    // 13. Verify the transaction is on-chain
    let raw_hex = rpc
        .get_raw_transaction(&iss_txid)
        .expect("getrawtransaction");
    let raw_bytes = hex::decode(&raw_hex).expect("hex decode");
    let on_chain_tx = Transaction::read(
        &raw_bytes[..],
        BranchId::for_height(&params, BlockHeight::from_u32(sync2.height)),
    )
    .expect("parse on-chain tx");

    // 14. Verify the issue bundle
    let ib = on_chain_tx
        .issue_bundle()
        .expect("on-chain tx has issue bundle");

    let ib_actions = ib.actions();
    assert!(
        ib_actions.len() >= 1,
        "Expected >=1 issue action, got {}",
        ib_actions.len()
    );

    let all_notes = ib.get_all_notes();
    assert!(
        all_notes.len() >= 2,
        "Expected >=2 issue notes (reference + issued), got {}",
        all_notes.len()
    );

    assert_eq!(
        ib_actions[0].asset_desc_hash(),
        &desc_hash,
        "Asset desc hash mismatch"
    );

    println!(
        "SUCCESS: issuance tx confirmed with {} issue actions, {} notes",
        ib_actions.len(),
        all_notes.len()
    );
}
