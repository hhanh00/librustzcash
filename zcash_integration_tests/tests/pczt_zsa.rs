//! Integration test: PCZT pipeline with ZSA asset transfer, end-to-end against zebra.
//!
//! Demonstrates using the PCZT multi-role collaborative transaction construction
//! API to transfer a custom ZSA asset through all roles.
//!
//! Flow:
//!   1. Shield ZEC (direct builder) → get orchard zatoshi note
//!   2. Issue custom asset (direct builder) → get custom asset note
//!   3. Transfer custom asset (PCZT roles) → spend custom note + zatoshi fee
//!
//! Requires a running zebra node with NU7 support in regtest mode.

use nonempty::NonEmpty;
use orchard::{
    circuit::ProvingKey,
    flavor::OrchardZSA,
    issuance::{auth::IssueAuthKey, compute_asset_desc_hash},
    note::AssetBase,
    value::NoteValue,
};
use pczt::roles::{
    creator::Creator,
    io_finalizer::IoFinalizer,
    prover::Prover,
    signer::Signer,
    spend_finalizer::SpendFinalizer,
    tx_extractor::TransactionExtractor,
};
use transparent::builder::TransparentSigningSet;
use zcash_primitives::transaction::{
    Transaction,
    builder::{BuildConfig, Builder},
    fees::zip317,
};
use zcash_protocol::{
    consensus::{BlockHeight, BranchId, Parameters},
    local_consensus::LocalNetwork,
    memo::MemoBytes,
    value::Zatoshis,
};

mod common;

use common::build::{parse_txid, tx_to_hex};
use common::keys::{
    encode_transparent_address, make_orchard_account, make_transparent_account, orchard_sak,
};
use common::rpc::RpcClient;
use common::tree::OrchardTreeState;

/// Syncs the entire chain from genesis to tip into an Orchard tree,
/// and returns the tree along with the 0-based global position of the
/// first orchard cmx in the given block.
fn sync_all_blocks_for_block(
    rpc: &RpcClient,
    params: &impl Parameters,
    target_block_hash: &str,
) -> (OrchardTreeState, usize) {
    let mut tree = OrchardTreeState::new();
    let mut first_pos: Option<usize> = None;

    // Walk from tip back to genesis, collecting block hashes.
    let mut block_hashes: Vec<(String, u32)> = Vec::new();
    let mut h = rpc.get_best_block_hash().expect("best block hash");
    loop {
        let block = rpc.get_block(&h).expect("get block");
        let height = block["height"].as_u64().unwrap() as u32;
        block_hashes.push((h.clone(), height));
        if height <= 1 {
            break;
        }
        h = block["previousblockhash"].as_str().unwrap().to_string();
    }
    block_hashes.reverse(); // genesis first

    for (hash, height) in &block_hashes {
        let is_target_block = hash == target_block_hash;
        if is_target_block {
            println!("matched target block at height={height} hash={hash}");
        }
        let block = rpc.get_block(hash).expect("get block");
        let txs = block["tx"].as_array().unwrap();
        let branch = BranchId::for_height(params, BlockHeight::from_u32(*height));

        for tx_json in txs {
            let hex_str = tx_json["hex"].as_str().unwrap();
            let raw = hex::decode(hex_str).unwrap();
            match zcash_primitives::transaction::Transaction::read(&raw[..], branch) {
                Ok(tx) => {
                    if let Some(ob) = tx.orchard_bundle() {
                        let zsa_bundle = ob.as_zsa_bundle();
                        let n_actions = zsa_bundle.actions().len();
                        if is_target_block {
                            println!("  block {height}: tx with {n_actions} orchard actions");
                        }
                        for action in zsa_bundle.actions() {
                            if is_target_block && first_pos.is_none() {
                                first_pos = Some(tree.leaf_count());
                            }
                            let leaf = orchard::tree::MerkleHashOrchard::from_cmx(action.cmx());
                            tree.append_leaf(leaf);
                        }
                    }
                    #[cfg(zcash_unstable = "nu7")]
                    if let Some(ib) = tx.issue_bundle() {
                        let n_notes: usize = ib.actions().iter().map(|a| a.notes().len()).sum();
                        if is_target_block {
                            println!("  block {height}: tx with {n_notes} issue notes");
                        }
                        for note in ib.actions().iter().flat_map(|a| a.notes()) {
                            let leaf = orchard::tree::MerkleHashOrchard::from_cmx(
                                &orchard::note::ExtractedNoteCommitment::from(note.commitment()),
                            );
                            tree.append_leaf(leaf);
                        }
                    }
                }
                Err(e) => {
                    if is_target_block {
                        println!("  block {height}: tx parse error: {e:?}");
                    }
                }
            }
        }
    }

    let pos = first_pos.expect("target block not found in chain");
    (tree, pos)
}

/// Scans ALL blocks from tip to genesis, counting orchard cmx per block,
/// and compares the local BridgeTree root against zebra's `finalorchardroot`.
#[test]
fn bridge_tree_root_all_blocks() {
    let rpc = RpcClient::new();
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

    // Walk from tip back to genesis, collecting block hashes
    let mut block_hashes: Vec<(String, u32)> = Vec::new();
    let mut h = rpc.get_best_block_hash().expect("best block hash");
    loop {
        let block = rpc.get_block(&h).expect("get block");
        let height = block["height"].as_u64().unwrap() as u32;
        block_hashes.push((h.clone(), height));
        if height <= 1 { break; }
        h = block["previousblockhash"].as_str().unwrap().to_string();
    }
    block_hashes.reverse(); // genesis first

    // Build local BridgeTree from ALL blocks
    let mut tree: bridgetree::BridgeTree<orchard::tree::MerkleHashOrchard, usize, 32> =
        bridgetree::BridgeTree::new(200);
    let mut total_cmx = 0usize;

    for (hash, height) in &block_hashes {
        let block = rpc.get_block(hash).expect("get block");
        let branch = BranchId::for_height(&params, BlockHeight::from_u32(*height));
        let mut block_cmx = 0usize;
        for tx_json in block["tx"].as_array().unwrap() {
            let hex_str = tx_json["hex"].as_str().unwrap();
            let raw = hex::decode(hex_str).unwrap();
            let tx = Transaction::read(&raw[..], branch).expect("tx parse");
            if let Some(ob) = tx.orchard_bundle() {
                for action in ob.as_zsa_bundle().actions() {
                    let leaf = orchard::tree::MerkleHashOrchard::from_cmx(action.cmx());
                    tree.append(leaf);
                    tree.mark();
                    block_cmx += 1;
                }
            }
        }
        let zebra_root = block["finalorchardroot"].as_str().unwrap_or("none");
        let local_root = tree.root(0).map(|r| hex::encode(r.to_bytes())).unwrap_or_else(|| "none".to_string());
        let status = if local_root == zebra_root { "MATCH" } else { "DIFF" };
        if block_cmx > 0 || status == "DIFF" {
            println!("block {height}: {block_cmx} cmx, local={local_root}, zebra={zebra_root} {status}");
        }
        total_cmx += block_cmx;
    }

    println!("total cmx across {} blocks: {total_cmx}", block_hashes.len());
    let tip = block_hashes.last().unwrap();
    let final_block = rpc.get_block(&tip.0).expect("get tip");
    let zebra_final = final_block["finalorchardroot"].as_str().unwrap_or("none");
    let local_final = tree.root(0).map(|r| hex::encode(r.to_bytes())).unwrap_or_else(|| "none".to_string());
    println!("final: local={local_final}, zebra={zebra_final}, match={}", local_final == zebra_final);
}

#[test]
#[cfg(zcash_unstable = "nu7")]
fn test_pczt_zsa_shielding() {
    let rpc = RpcClient::new();

    let info = rpc.get_blockchain_info().expect("getblockchaininfo");
    let chain = info["chain"].as_str().expect("chain field");
    assert!(chain == "regtest" || chain == "test", "regtest required, got {chain}");

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

    // ── Keys ──
    let (_tsk, taddr, t_sk) = make_transparent_account(b"0123456789ABCDEF0123456789ABCDEF");
    let taddr_str = encode_transparent_address(&taddr, zcash_protocol::consensus::NetworkType::Regtest);
    let (orchard_sk, orchard_fvk, orchard_addr) = make_orchard_account(&[0x01; 32]);
    let orch_sak = orchard_sak(&orchard_sk);
    let isk = IssueAuthKey::<orchard::issuance::auth::ZSASchnorr>::from_zip32_seed(
        b"zsa_int_issue_seed01", 1, 0,
    ).expect("issue auth key");
    let t_pubkey = t_sk.public_key(&secp256k1::Secp256k1::signing_only());

    let mut signing_set = TransparentSigningSet::new();
    signing_set.add_key(t_sk.clone());

    // ── Step 1: Mine blocks and shield ZEC via direct builder ──
    let _ = rpc.generate(101).expect("generate");
    let info = rpc.get_blockchain_info().expect("getblockchaininfo");
    let height = info["blocks"].as_u64().expect("blocks") as u32;

    let utxos = rpc.get_address_utxos(&taddr_str).expect("getaddressutxos");
    let utxo = &utxos[0];
    let txid: String = utxo["txid"].as_str().expect("txid").to_string();
    let vout = utxo["outputIndex"].as_u64().expect("outputIndex") as u32;
    let amount: u64 = utxo["satoshis"].as_u64().expect("satoshis");

    let outpoint_hash = parse_txid(&txid).expect("parse txid");
    let outpoint = transparent::bundle::OutPoint::new(outpoint_hash, vout);
    let coin_value = Zatoshis::from_u64(amount).expect("valid amount");
    let coin_script: transparent::address::Script = taddr.script().into();

    let shield_result = common::build::build_shielding_tx(
        &params,
        BlockHeight::from_u32(height + 1),
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
    ).expect("build shielding tx");

    let shield_tx = shield_result.into_transaction();
    let shield_txid = rpc.send_raw_transaction(&tx_to_hex(&shield_tx).expect("hex")).expect("send");
    rpc.generate(1).expect("generate after shield");
    let shield_block = rpc.wait_for_confirmation(&shield_txid).expect("confirm");
    println!("PCZT ZSA shielding confirmed: {shield_txid}");
    println!("shield_block hash = {shield_block}");

    // ── Step 2: Track the orchard note from shielding ──
    // Sync the ENTIRE chain to build the correct orchard tree, instead of
    // relying on single-block sync which depends on a clean initial state.
    let (mut tree, tx_first_pos) = sync_all_blocks_for_block(&rpc, &params, &shield_block);

    // Verify our tree matches zebra
    let zebra_root = rpc.get_orchard_root(&shield_block).expect("zebra root");
    assert_eq!(
        hex::encode(tree.anchor().to_bytes()),
        zebra_root,
        "synced-tree anchor must match zebra"
    );

    // Decrypt our output note to find which cmx (action index) it corresponds to
    let orchard_bundle = shield_tx.orchard_bundle().expect("orchard bundle");
    let zsa = orchard_bundle.as_zsa_bundle();
    let ivk = orchard_fvk.to_ivk(orchard::keys::Scope::External);
    let decrypted = zsa.decrypt_outputs_with_keys(&[ivk]);
    let (note_idx, _, orchard_note, _, _) = decrypted.into_iter().next().expect("decrypt");

    let note_global_pos = tx_first_pos + note_idx;
    let anchor = tree.anchor();
    let merkle_path = tree.witness(note_global_pos);

    // ── Step 3: Issue a custom asset (WETH) via PCZT Issuer role ──
    // Generate an empty block so the shield anchor has depth.
    rpc.generate(1).expect("generate block between shield and issue");

    let desc_hash = compute_asset_desc_hash(&NonEmpty::from_slice(b"WETH").unwrap());

    let utxos2 = rpc.get_address_utxos(&taddr_str).expect("getaddressutxos after shield");
    let utxo2 = &utxos2[0];
    let txid2: String = utxo2["txid"].as_str().expect("txid").to_string();
    let vout2 = utxo2["outputIndex"].as_u64().expect("outputIndex") as u32;
    let amount2: u64 = utxo2["satoshis"].as_u64().expect("satoshis");
    let outpoint_hash2 = parse_txid(&txid2).expect("parse txid2");
    let outpoint2 = transparent::bundle::OutPoint::new(outpoint_hash2, vout2);
    let coin_value2 = Zatoshis::from_u64(amount2).expect("valid amount");
    let coin_script2: transparent::address::Script = taddr.script().into();

    // Build the issuance PCZT to exercise the Issuer role.
    let orchard_zec_change = Zatoshis::from_u64(
        amount2 + orchard_note.value().inner() - 2_000_000,
    ).unwrap_or(Zatoshis::const_from_u64(1));
    let transparent_change = Zatoshis::const_from_u64(1_985_000);

    let config = BuildConfig::Standard {
        sapling_anchor: None,
        orchard_anchor: Some(anchor),
    };

    let mut pczt_builder = Builder::new(&params, BlockHeight::from_u32(height + 3), config);
    pczt_builder.add_transparent_p2pkh_input(t_pubkey, outpoint2, transparent::bundle::TxOut::new(coin_value2, coin_script2.clone())).expect("add transparent input");
    pczt_builder.add_orchard_spend::<zip317::FeeError>(orchard_fvk.clone(), orchard_note.clone(), merkle_path.clone()).expect("add orchard spend");
    pczt_builder.add_orchard_output::<zip317::FeeError>(Some(orchard_fvk.to_ovk(orchard::keys::Scope::External)), orchard_addr, orchard_zec_change, AssetBase::zatoshi(), MemoBytes::empty()).expect("add orchard zec change");
    pczt_builder.add_transparent_output(&taddr, transparent_change).expect("add transparent change");

    let pczt_result = pczt_builder.build_for_pczt::<_, zip317::FeeRule>(rand_core::OsRng, &zip317::FeeRule::standard(), #[cfg(zcash_unstable = "nu7")] |_| false).expect("build_for_pczt");

    // Save orchard metadata for correct action indexing after shuffling.
    let orchard_meta = pczt_result.orchard_meta;

    // Build the ZSA issuance bundle
    let mut zsa_builder = zcash_primitives::transaction::zsa_builder::ZsaBuilder::new(isk.clone());
    zsa_builder.add_issue_output(desc_hash, orchard_addr, NoteValue::from_raw(1_000_000), true, &mut rand_core::OsRng).expect("add issue output");

    // Run the full PCZT pipeline with Issuer role.
    let pczt = Creator::build_from_parts(pczt_result.pczt_parts).expect("creator");
    let pczt = pczt::roles::issuer::Issuer::new(pczt)
        .build_awaiting_sighash(zsa_builder, rand_core::OsRng)
        .expect("issuer p1");
    let pczt = IoFinalizer::new(pczt).finalize_io().expect("io finalizer");
    let pczt = pczt::roles::issuer::Issuer::new(pczt)
        .sign(&isk)
        .expect("issuer p2");

    // Verify the PCZT has a signed issue bundle
    assert!(pczt.issue().is_initialized(), "PCZT should have issue data");
    assert!(pczt.issue().to_signed().is_some(), "PCZT should have signed issue bundle");

    let pk = ProvingKey::build::<OrchardZSA>();
    let pczt = Prover::new(pczt).create_orchard_proof(&pk).expect("prover").finish();

    let pczt = {
        let signer = Signer::new(pczt).expect("signer new");
        let mut signer = signer;
        signer.sign_transparent(0, &t_sk).expect("sign transparent");
        // The orchard builder shuffles actions; use the metadata to find the
        // correct index for our spend.
        let spend_idx = orchard_meta.spend_action_index(0).expect("orchard spend index");
        if let Err(e) = signer.sign_orchard(spend_idx, &orch_sak) {
            panic!("orchard sign (idx {spend_idx}): {e:?}");
        }
        signer.finish()
    };

    let pczt = SpendFinalizer::new(pczt).finalize_spends().expect("spend finalizer");
    let iss_tx = TransactionExtractor::new(pczt).extract().expect("tx extractor");

    let iss_txid = rpc.send_raw_transaction(&tx_to_hex(&iss_tx).expect("hex")).expect("send issue");
    rpc.generate(1).expect("generate after issue");
    let iss_block = rpc.wait_for_confirmation(&iss_txid).expect("confirm issue");

    // ── Step 4: Verify issuance on-chain ──
    let _sync2 = tree.sync_block(&rpc, &iss_block, &params).expect("sync issue block");

    let ib = iss_tx.issue_bundle().expect("issue bundle");
    let ib_actions = ib.actions();
    assert!(ib_actions.len() >= 1, "Expected >=1 issue action");
    assert_eq!(ib_actions[0].asset_desc_hash(), &desc_hash, "Asset desc hash mismatch");

    let all_notes: Vec<_> = ib_actions.iter().flat_map(|a| a.notes()).collect();
    assert!(all_notes.len() >= 2, "Expected >=2 issue notes (reference + value)");

    println!("PCZT ZSA shielding + issuance confirmed: shield={shield_txid}, issue={iss_txid}");
}

#[test]
#[cfg(zcash_unstable = "nu7")]
fn test_pczt_zsa_transfer() {
    let rpc = RpcClient::new();

    let info = rpc.get_blockchain_info().expect("getblockchaininfo");
    let chain = info["chain"].as_str().expect("chain field");
    assert!(chain == "regtest" || chain == "test", "regtest required, got {chain}");

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

    // ── Keys ──
    let (_tsk, taddr, t_sk) = make_transparent_account(b"0123456789ABCDEF0123456789ABCDEF");
    let taddr_str = encode_transparent_address(&taddr, zcash_protocol::consensus::NetworkType::Regtest);
    let (orchard_sk, orchard_fvk, orchard_addr) = make_orchard_account(&[0x01; 32]);
    let orch_sak = orchard_sak(&orchard_sk);
    let isk = IssueAuthKey::<orchard::issuance::auth::ZSASchnorr>::from_zip32_seed(
        b"zsa_int_issue_seed01", 1, 0,
    ).expect("issue auth key");
    let t_pubkey = t_sk.public_key(&secp256k1::Secp256k1::signing_only());

    // ── Step 1: Mine blocks and shield ZEC ──
    let _ = rpc.generate(101).expect("generate");
    let info = rpc.get_blockchain_info().expect("getblockchaininfo");
    let height = info["blocks"].as_u64().expect("blocks") as u32;

    let utxos = rpc.get_address_utxos(&taddr_str).expect("getaddressutxos");
    let utxo = &utxos[0];
    let txid: String = utxo["txid"].as_str().expect("txid").to_string();
    let vout = utxo["outputIndex"].as_u64().expect("outputIndex") as u32;
    let amount: u64 = utxo["satoshis"].as_u64().expect("satoshis");

    let outpoint_hash = parse_txid(&txid).expect("parse txid");
    let outpoint = transparent::bundle::OutPoint::new(outpoint_hash, vout);
    let coin_value = Zatoshis::from_u64(amount).expect("valid amount");
    let coin_script: transparent::address::Script = taddr.script().into();

    let mut signing_set = TransparentSigningSet::new();
    signing_set.add_key(t_sk.clone());

    let shield_result = common::build::build_shielding_tx(
        &params,
        BlockHeight::from_u32(height + 1),
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
    ).expect("build shielding tx");

    let shield_tx = shield_result.into_transaction();
    let shield_txid = rpc.send_raw_transaction(&tx_to_hex(&shield_tx).expect("hex")).expect("send");
    rpc.generate(1).expect("generate");
    let shield_block = rpc.wait_for_confirmation(&shield_txid).expect("confirm");

    // Sync the ENTIRE chain to build the correct orchard tree, instead of
    // relying on single-block sync which depends on a clean initial state.
    let (mut tree, tx_first_pos) = sync_all_blocks_for_block(&rpc, &params, &shield_block);

    // Verify our tree matches zebra.
    let zebra_root = rpc.get_orchard_root(&shield_block).expect("zebra root");
    assert_eq!(
        hex::encode(tree.anchor().to_bytes()),
        zebra_root,
        "synced-tree anchor must match zebra"
    );

    let orchard_bundle = shield_tx.orchard_bundle().expect("orchard bundle");
    let zsa = orchard_bundle.as_zsa_bundle();
    let ivk = orchard_fvk.to_ivk(orchard::keys::Scope::External);
    let decrypted = zsa.decrypt_outputs_with_keys(&[ivk]);
    let (note_idx, _, orchard_note, _, _) = decrypted.into_iter().next().expect("decrypt");

    let note_global_pos = tx_first_pos + note_idx;
    let anchor = tree.anchor();
    let zec_merkle_path = tree.witness(note_global_pos);

    // ── Step 2: Issue a custom asset via PCZT ──
    // Generate an empty block so the shield anchor has depth.
    rpc.generate(1).expect("generate block between shield and issue");

    let desc_hash = compute_asset_desc_hash(&NonEmpty::from_slice(b"WETH").unwrap());

    let utxos2 = rpc.get_address_utxos(&taddr_str).expect("getaddressutxos");
    let utxo2 = &utxos2[0];
    let txid2: String = utxo2["txid"].as_str().expect("txid").to_string();
    let vout2 = utxo2["outputIndex"].as_u64().expect("outputIndex") as u32;
    let amount2: u64 = utxo2["satoshis"].as_u64().expect("satoshis");
    let outpoint_hash2 = parse_txid(&txid2).expect("parse txid2");
    let outpoint2 = transparent::bundle::OutPoint::new(outpoint_hash2, vout2);
    let coin_value2 = Zatoshis::from_u64(amount2).expect("valid amount");
    let coin_script2: transparent::address::Script = taddr.script().into();

    // Build the issuance PCZT.
    let orchard_zec_change = Zatoshis::from_u64(
        amount2 + orchard_note.value().inner() - 2_000_000,
    ).unwrap_or(Zatoshis::const_from_u64(1));
    let transparent_change = Zatoshis::const_from_u64(1_985_000);

    let iss_config = BuildConfig::Standard {
        sapling_anchor: None,
        orchard_anchor: Some(anchor),
    };

    // Get the shield block height for the issuance builder.
    let shield_height = rpc.get_block(&shield_block)
        .and_then(|b| b["height"].as_u64().ok_or("missing height".to_string()))
        .expect("shield block height") as u32;
    let mut iss_builder = Builder::new(&params, BlockHeight::from_u32(shield_height + 1), iss_config);
    iss_builder
        .add_transparent_p2pkh_input(t_pubkey, outpoint2, transparent::bundle::TxOut::new(coin_value2, coin_script2.clone()))
        .expect("add transparent input");
    iss_builder
        .add_orchard_spend::<zip317::FeeError>(orchard_fvk.clone(), orchard_note.clone(), zec_merkle_path.clone())
        .expect("add orchard spend");
    iss_builder
        .add_orchard_output::<zip317::FeeError>(
            Some(orchard_fvk.to_ovk(orchard::keys::Scope::External)),
            orchard_addr,
            orchard_zec_change,
            AssetBase::zatoshi(),
            MemoBytes::empty(),
        )
        .expect("add orchard zec change");
    iss_builder
        .add_transparent_output(&taddr, transparent_change)
        .expect("add transparent change");

    let iss_pczt_result = iss_builder
        .build_for_pczt::<_, zip317::FeeRule>(
            rand_core::OsRng,
            &zip317::FeeRule::standard(),
            |_| false,
        )
        .expect("build_for_pczt issuance");
    let iss_orchard_meta = iss_pczt_result.orchard_meta;

    // Build the ZSA issuance bundle externally (then wire through Issuer role).
    let mut zsa_builder =
        zcash_primitives::transaction::zsa_builder::ZsaBuilder::new(isk.clone());
    zsa_builder
        .add_issue_output(
            desc_hash,
            orchard_addr,
            NoteValue::from_raw(1_000_000),
            true,
            &mut rand_core::OsRng,
        )
        .expect("add issue output");

    let pczt = Creator::build_from_parts(iss_pczt_result.pczt_parts).expect("creator");
    let pczt = pczt::roles::issuer::Issuer::new(pczt)
        .build_awaiting_sighash(zsa_builder, rand_core::OsRng)
        .expect("issuer p1");
    let pczt = IoFinalizer::new(pczt).finalize_io().expect("io finalizer");
    let pczt = pczt::roles::issuer::Issuer::new(pczt)
        .sign(&isk)
        .expect("issuer p2");

    let pk = ProvingKey::build::<OrchardZSA>();
    let pczt = Prover::new(pczt).create_orchard_proof(&pk).expect("prover").finish();

    let pczt = {
        let signer = Signer::new(pczt).expect("signer new");
        let mut signer = signer;
        signer.sign_transparent(0, &t_sk).expect("sign transparent");
        let spend_idx = iss_orchard_meta.spend_action_index(0).expect("orchard spend index");
        signer.sign_orchard(spend_idx, &orch_sak).expect("sign orchard");
        signer.finish()
    };

    let pczt = SpendFinalizer::new(pczt).finalize_spends().expect("spend finalizer");
    let iss_tx = TransactionExtractor::new(pczt).extract().expect("tx extractor");

    let iss_txid = rpc.send_raw_transaction(&tx_to_hex(&iss_tx).expect("hex")).expect("send issue");
    rpc.generate(1).expect("generate after issue");
    let iss_block = rpc.wait_for_confirmation(&iss_txid).expect("confirm issue");

    // Sync to get our custom asset note.
    let sync2 = tree.sync_block(&rpc, &iss_block, &params).expect("sync issue block");
    let ib = iss_tx.issue_bundle().expect("issue bundle");
    let issue_notes: Vec<_> = ib.actions().iter().flat_map(|a| a.notes()).collect();
    let issue_note = (*issue_notes.last().expect("at least one issued note")).clone();
    // Issue notes are appended AFTER orchard cmx in the block.
    // The issued note is the last cmx in the issuance block.
    let issue_pos = sync2.count_after - 1; // last cmx added in this block
    let issue_anchor = tree.anchor();
    let issue_merkle_path = tree.witness(issue_pos);

    // ── Step 3: Transfer custom asset via PCZT ──
    let custom_asset = issue_note.asset();
    assert_ne!(custom_asset, AssetBase::zatoshi());

    // Get another UTXO for zatoshi fee.
    let utxos3 = rpc.get_address_utxos(&taddr_str).expect("getaddressutxos");
    let utxo3 = &utxos3[0];
    let txid3: String = utxo3["txid"].as_str().expect("txid").to_string();
    let vout3 = utxo3["outputIndex"].as_u64().expect("outputIndex") as u32;
    let amount3: u64 = utxo3["satoshis"].as_u64().expect("satoshis");
    let outpoint_hash3 = parse_txid(&txid3).expect("parse txid3");
    let outpoint3 = transparent::bundle::OutPoint::new(outpoint_hash3, vout3);
    let coin_value3 = Zatoshis::from_u64(amount3).expect("valid amount");
    let coin_script3: transparent::address::Script = taddr.script().into();

    // Build the transfer via PCZT.
    let config = BuildConfig::Standard {
        sapling_anchor: None,
        orchard_anchor: Some(issue_anchor),
    };

    let mut builder = Builder::new(&params, BlockHeight::from_u32(sync2.height + 1), config);
    builder
        .add_transparent_p2pkh_input(
            t_pubkey,
            outpoint3,
            transparent::bundle::TxOut::new(coin_value3, coin_script3),
        )
        .expect("add transparent input for fee");
    builder
        .add_orchard_spend::<zip317::FeeError>(
            orchard_fvk.clone(),
            issue_note,
            issue_merkle_path,
        )
        .expect("add orchard spend");
    builder
        .add_orchard_output::<zip317::FeeError>(
            None,
            orchard_addr,
            Zatoshis::const_from_u64(1_000_000),
            custom_asset,
            MemoBytes::empty(),
        )
        .expect("add custom output");
    builder
        .add_transparent_output(&taddr, Zatoshis::const_from_u64(624_985_000))
        .expect("add transparent change");
    let pczt_result = builder
        .build_for_pczt::<_, zip317::FeeRule>(
            rand_core::OsRng,
            &zip317::FeeRule::standard(),
            |_| false,
        )
        .expect("build_for_pczt");

    // Save orchard metadata for correct action indexing after shuffling.
    let orchard_meta = pczt_result.orchard_meta;

    // ── PCZT Roles ──
    let pczt = Creator::build_from_parts(pczt_result.pczt_parts).expect("creator");
    let pczt = IoFinalizer::new(pczt).finalize_io().expect("io finalizer");

    let pk = ProvingKey::build::<OrchardZSA>();
    let pczt = Prover::new(pczt).create_orchard_proof(&pk).expect("prover").finish();

    let pczt = {
        let mut signer = Signer::new(pczt).expect("signer new");
        signer.sign_transparent(0, &t_sk).expect("sign transparent");
        let spend_idx = orchard_meta.spend_action_index(0).expect("orchard spend index");
        signer.sign_orchard(spend_idx, &orch_sak).expect("sign orchard");
        signer.finish()
    };

    let pczt = SpendFinalizer::new(pczt).finalize_spends().expect("spend finalizer");
    let tx = TransactionExtractor::new(pczt).extract().expect("tx extractor");

    let tx_hex = tx_to_hex(&tx).expect("serialize");
    let txid = rpc.send_raw_transaction(&tx_hex).expect("send pczt transfer");
    rpc.generate(1).expect("generate after transfer");
    rpc.wait_for_confirmation(&txid).expect("confirm pczt transfer");
    println!("PCZT ZSA transfer confirmed: {txid}");
}
