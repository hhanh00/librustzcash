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

use common::build::{build_issuance_tx, parse_txid, tx_to_hex};
use common::keys::{
    encode_transparent_address, make_orchard_account, make_transparent_account, orchard_sak,
};
use common::rpc::RpcClient;
use common::tree::OrchardTreeState;

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

    let (_tsk, taddr, t_sk) = make_transparent_account(b"0123456789ABCDEF0123456789ABCDEF");
    let taddr_str = encode_transparent_address(&taddr, zcash_protocol::consensus::NetworkType::Regtest);
    let (_orchard_sk, _orchard_fvk, orchard_addr) = make_orchard_account(&[0x01; 32]);

    let _ = rpc.generate(101).expect("generate");
    let info = rpc.get_blockchain_info().expect("getblockchaininfo");
    let current_height = info["blocks"].as_u64().expect("blocks") as u32;

    let utxos = rpc.get_address_utxos(&taddr_str).expect("getaddressutxos");
    let utxo = &utxos[0];
    let txid: String = utxo["txid"].as_str().expect("txid").to_string();
    let vout = utxo["outputIndex"].as_u64().expect("outputIndex") as u32;
    let amount: u64 = utxo["satoshis"].as_u64().expect("satoshis");

    let t_pubkey = t_sk.public_key(&secp256k1::Secp256k1::signing_only());
    let outpoint_hash = parse_txid(&txid).expect("parse txid");
    let outpoint = transparent::bundle::OutPoint::new(outpoint_hash, vout);
    let coin_value = Zatoshis::from_u64(amount).expect("valid amount");
    let coin_script: transparent::address::Script = taddr.script().into();

    let zec_fee = 15_000u64;
    let change_amount = 35_000u64;
    let orchard_value = Zatoshis::from_u64(amount.saturating_sub(zec_fee + change_amount))
        .unwrap_or(Zatoshis::const_from_u64(1));

    let config = BuildConfig::Standard {
        sapling_anchor: None,
        orchard_anchor: Some(orchard::Anchor::empty_tree()),
    };

    let mut builder = Builder::new(&params, BlockHeight::from_u32(current_height + 1), config);
    builder.add_transparent_p2pkh_input(t_pubkey, outpoint, transparent::bundle::TxOut::new(coin_value, coin_script)).expect("add transparent input");
    builder.add_orchard_output::<zip317::FeeError>(None, orchard_addr, orchard_value, AssetBase::zatoshi(), MemoBytes::empty()).expect("add orchard output");
    builder.add_transparent_output(&taddr, Zatoshis::const_from_u64(change_amount)).expect("add transparent change");

    let pczt_result = builder.build_for_pczt::<_, zip317::FeeRule>(rand_core::OsRng, &zip317::FeeRule::standard(), #[cfg(zcash_unstable = "nu7")] |_| false).expect("build_for_pczt");

    let pczt = Creator::build_from_parts(pczt_result.pczt_parts).expect("creator");
    let pczt = IoFinalizer::new(pczt).finalize_io().expect("io finalizer");

    let pk = ProvingKey::build::<OrchardZSA>();
    let pczt = Prover::new(pczt).create_orchard_proof(&pk).expect("prover").finish();

    let mut signer = pczt::roles::signer::Signer::new(pczt).expect("signer new");
    signer.sign_transparent(0, &t_sk).expect("sign transparent");
    let pczt = signer.finish();

    let pczt = pczt::roles::spend_finalizer::SpendFinalizer::new(pczt).finalize_spends().expect("finalize spends");
    let tx = TransactionExtractor::new(pczt).extract().expect("tx extractor");

    let tx_hex = tx_to_hex(&tx).expect("serialize");
    let txid = rpc.send_raw_transaction(&tx_hex).expect("send pczt shield");
    rpc.generate(1).expect("generate after shield");
    rpc.wait_for_confirmation(&txid).expect("confirm pczt shield");
    println!("PCZT ZSA shielding confirmed: {txid}");
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

    let mut tree = OrchardTreeState::new();
    let sync = tree.sync_block(&rpc, &shield_block, &params).expect("sync shield block");
    let anchor = tree.anchor();

    let orchard_bundle = shield_tx.orchard_bundle().expect("orchard bundle");
    let zsa = orchard_bundle.as_zsa_bundle();
    let ivk = orchard_fvk.to_ivk(orchard::keys::Scope::External);
    let decrypted = zsa.decrypt_outputs_with_keys(&[ivk]);
    let (note_idx, _, orchard_note, _, _) = decrypted.into_iter().next().expect("decrypt");
    let note_pos = sync.count_before + note_idx;
    let zec_merkle_path = tree.witness(note_pos);

    assert_eq!(
        hex::encode(anchor.to_bytes()),
        rpc.get_orchard_root(&shield_block).expect("zebra anchor"),
        "local anchor must match zebra"
    );

    // ── Step 2: Issue a custom asset ──
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

    let iss_result = build_issuance_tx(
        &params,
        BlockHeight::from_u32(height + 3),
        t_pubkey,
        outpoint2,
        coin_value2,
        coin_script2,
        taddr,
        &orchard_fvk,
        orchard_note,
        zec_merkle_path,
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
    ).expect("build issuance tx");

    let iss_tx = iss_result.into_transaction();
    let iss_txid = rpc.send_raw_transaction(&tx_to_hex(&iss_tx).expect("hex")).expect("send issue");
    rpc.generate(1).expect("generate after issue");
    let iss_block = rpc.wait_for_confirmation(&iss_txid).expect("confirm issue");

    // Sync to get our custom asset note
    let sync2 = tree.sync_block(&rpc, &iss_block, &params).expect("sync issue block");
    let ib = iss_tx.issue_bundle().expect("issue bundle");
    let issue_notes: Vec<_> = ib.actions().iter().flat_map(|a| a.notes()).collect();
    let issue_note = (*issue_notes.last().expect("at least one issued note")).clone();
    // Issue notes are appended AFTER orchard cmx in the block.
    // The issued note is the last cmx in the issuance block.
    let _issue_note_idx = issue_notes.len() - 1;
    let issue_pos = sync2.count_after - 1; // last cmx added in this block
    let issue_anchor = tree.anchor();
    let issue_merkle_path = tree.witness(issue_pos);

    // ── Step 3: Transfer custom asset via PCZT ──
    let custom_asset = issue_note.asset();
    assert_ne!(custom_asset, AssetBase::zatoshi());

    // Get another UTXO for zatoshi fee
    let utxos3 = rpc.get_address_utxos(&taddr_str).expect("getaddressutxos");
    let utxo3 = &utxos3[0];
    let txid3: String = utxo3["txid"].as_str().expect("txid").to_string();
    let vout3 = utxo3["outputIndex"].as_u64().expect("outputIndex") as u32;
    let amount3: u64 = utxo3["satoshis"].as_u64().expect("satoshis");
    let outpoint_hash3 = parse_txid(&txid3).expect("parse txid3");
    let outpoint3 = transparent::bundle::OutPoint::new(outpoint_hash3, vout3);
    let coin_value3 = Zatoshis::from_u64(amount3).expect("valid amount");
    let coin_script3: transparent::address::Script = taddr.script().into();

    // Build the transfer via PCZT
    let config = BuildConfig::Standard {
        sapling_anchor: None,
        orchard_anchor: Some(issue_anchor),
    };

    let mut builder = Builder::new(&params, BlockHeight::from_u32(sync2.height + 1), config);
    // Transparent input for zatoshi fees + change
    builder
        .add_transparent_p2pkh_input(
            t_pubkey,
            outpoint3,
            transparent::bundle::TxOut::new(coin_value3, coin_script3),
        )
        .expect("add transparent input for fee");
    // Spend the custom asset note
    builder
        .add_orchard_spend::<zip317::FeeError>(
            orchard_fvk.clone(),
            issue_note,
            issue_merkle_path,
        )
        .expect("add orchard spend");
    // Output: send custom asset back (zatoshi value is 0 for non-ZEC assets)
    builder
        .add_orchard_output::<zip317::FeeError>(
            None,
            orchard_addr,
            Zatoshis::const_from_u64(0),
            custom_asset,
            MemoBytes::empty(),
        )
        .expect("add custom output");
    // Change = 624_985_000 (from ChangeRequired with placeholder=0)
    builder
        .add_transparent_output(&taddr, Zatoshis::const_from_u64(624_985_000))
        .expect("add transparent change");
    let pczt_result = builder
        .build_for_pczt::<_, zip317::FeeRule>(
            rand_core::OsRng,
            &zip317::FeeRule::standard(),
            #[cfg(zcash_unstable = "nu7")]
            |_| false,
        )
        .expect("build_for_pczt");

    // ── PCZT Roles ──
    let pczt = Creator::build_from_parts(pczt_result.pczt_parts).expect("creator");
    let pczt = IoFinalizer::new(pczt).finalize_io().expect("io finalizer");

    let pk = ProvingKey::build::<OrchardZSA>();
    let pczt = Prover::new(pczt).create_orchard_proof(&pk).expect("prover").finish();

    let pczt = {
        let mut signer = Signer::new(pczt).expect("signer new");
        signer.sign_transparent(0, &t_sk).expect("sign transparent");
        signer.sign_orchard(0, &orch_sak).expect("sign orchard");
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
