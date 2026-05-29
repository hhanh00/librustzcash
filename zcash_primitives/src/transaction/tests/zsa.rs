//! Tests for the ZsaBuilder API and the issuance/transfer/burn lifecycle.

#[cfg(all(test, zcash_unstable = "nu7"))]
mod zsa_builder_tests {
    use crate::transaction::{
        builder::{BuildConfig, Builder},
        fees::zip317,
        zsa_builder::ZsaBuilder,
    };
    use incrementalmerkletree::Retention;
    use nonempty::NonEmpty;
    use orchard::{
        builder::BundleType,
        flavor::OrchardZSA,
        issuance::auth::{IssueAuthKey, IssueValidatingKey},
        issuance::compute_asset_desc_hash,
        keys::{FullViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
        note::{AssetBase, AssetId},
        primitives::OrchardDomain,
        tree::MerkleHashOrchard,
        value::NoteValue,
        Anchor,
    };
    use rand_core::OsRng;
    use shardtree::{ShardTree, store::memory::MemoryShardStore};
    use zcash_note_encryption::try_note_decryption;
    use zcash_protocol::{
        consensus::{BlockHeight, NetworkUpgrade, Parameters, TEST_NETWORK},
        memo::MemoBytes,
        value::Zatoshis,
    };
    use ::sapling;
    use ::transparent::builder::TransparentSigningSet;
    use zip32::AccountId;

    fn nu7_height() -> BlockHeight {
        TEST_NETWORK.activation_height(NetworkUpgrade::Nu7).unwrap()
    }

    fn no_new_assets(_: &AssetBase) -> bool {
        false
    }

    // Helper: creates an Orchard note for spending.
    fn create_test_note(value: u64) -> (
        orchard::Note, FullViewingKey, SpendingKey, orchard::Address,
        Anchor, orchard::tree::MerklePath,
    ) {
        let mut rng = OsRng;
        let sk = SpendingKey::from_zip32_seed(&[1u8; 32], 1, AccountId::ZERO).unwrap();
        let fvk = FullViewingKey::from(&sk);
        let recipient = fvk.address_at(0u32, Scope::External);
        let mut ob = orchard::builder::Builder::new(BundleType::DEFAULT, Anchor::empty_tree());
        ob.add_output(None, recipient, NoteValue::from_raw(value), AssetBase::zatoshi(), [0u8; 512])
            .unwrap();
        let (bundle, meta) = ob.build::<i64, OrchardZSA>(&mut rng).unwrap().unwrap();
        let action = bundle.actions().get(meta.output_action_index(0).unwrap()).unwrap();
        let (note, _, _) = try_note_decryption(
            &OrchardDomain::for_action(action), &fvk.to_ivk(Scope::External).prepare(), action,
        ).unwrap();
        let leaf = MerkleHashOrchard::from_cmx(&note.commitment().into());
        let mut tree = ShardTree::<_, 32, 16>::new(
            MemoryShardStore::<MerkleHashOrchard, u32>::empty(), 100,
        );
        tree.append(leaf, Retention::Marked).unwrap();
        tree.checkpoint(9_999_999).unwrap();
        let path = tree.witness_at_checkpoint_depth(0.into(), 0).unwrap().unwrap();
        (note, fvk, sk, recipient, path.root(leaf).into(), path.into())
    }

    // -----------------------------------------------------------------
    // 1. Single asset issuance (standalone ZsaBuilder)
    // -----------------------------------------------------------------
    #[test]
    fn test_issuance_single_asset() {
        let mut rng = OsRng;
        let isk = IssueAuthKey::<orchard::issuance::auth::ZSASchnorr>::from_zip32_seed(
            &[2u8; 32], 1, 0).unwrap();
        let ik = IssueValidatingKey::from(&isk);
        let (note, fvk, sk, recipient, anchor, merkle_path) = create_test_note(10_000_000);
        let desc_hash = compute_asset_desc_hash(&NonEmpty::from_slice(b"WETH").unwrap());
        let asset = AssetBase::custom(&AssetId::new_v0(&ik, &desc_hash));

        let mut zsa = ZsaBuilder::new(isk);
        let got = zsa.add_issue_output(desc_hash, recipient, NoteValue::from_raw(1_000_000), true, &mut rng).unwrap();
        assert_eq!(got, asset);
        assert!(zsa.is_initialized());

        let mut builder = Builder::new(TEST_NETWORK, nu7_height(), BuildConfig::Standard {
            sapling_anchor: Some(sapling::Anchor::empty_tree()),
            orchard_anchor: Some(anchor),
        });
        builder.set_zsa_builder(zsa);
        builder.add_orchard_spend::<zip317::FeeRule>(fvk.clone(), note, merkle_path).unwrap();
        builder.add_orchard_output::<zip317::FeeRule>(
            Some(fvk.to_ovk(Scope::External)), recipient,
            Zatoshis::from_u64(9_480_000).unwrap(), AssetBase::zatoshi(), MemoBytes::empty(),
        ).unwrap();

        let tx = builder.mock_build(
            &TransparentSigningSet::new(), &[], &[SpendAuthorizingKey::from(&sk)],
            |a| a == &asset, &mut rng,
        ).unwrap().into_transaction();

        let ib = tx.issue_bundle().unwrap();
        assert_eq!(ib.actions().len(), 1);
        assert_eq!(ib.get_all_notes().len(), 2);
    }

    // -----------------------------------------------------------------
    // 2. Multi-asset issuance (add_issue_output convenience)
    // -----------------------------------------------------------------
    #[test]
    fn test_issuance_multi_asset() {
        let mut rng = OsRng;
        let isk = IssueAuthKey::<orchard::issuance::auth::ZSASchnorr>::from_zip32_seed(
            &[3u8; 32], 1, 0).unwrap();
        let (note, fvk, sk, recipient, anchor, merkle_path) = create_test_note(100_000_000);
        let weth = compute_asset_desc_hash(&NonEmpty::from_slice(b"WETH").unwrap());
        let usdc = compute_asset_desc_hash(&NonEmpty::from_slice(b"USDC").unwrap());
        let wbtc = compute_asset_desc_hash(&NonEmpty::from_slice(b"WBTC").unwrap());

        let mut builder = Builder::new(TEST_NETWORK, nu7_height(), BuildConfig::Standard {
            sapling_anchor: Some(sapling::Anchor::empty_tree()),
            orchard_anchor: Some(anchor),
        });
        builder.add_orchard_spend::<zip317::FeeRule>(fvk.clone(), note, merkle_path).unwrap();

        let a1 = builder.add_issue_output::<zip317::FeeRule>(
            &isk, weth, recipient, NoteValue::from_raw(1), true).unwrap();
        let a2 = builder.add_issue_output::<zip317::FeeRule>(
            &isk, usdc, recipient, NoteValue::from_raw(1), true).unwrap();
        let a3 = builder.add_issue_output::<zip317::FeeRule>(
            &isk, wbtc, recipient, NoteValue::from_raw(1), true).unwrap();
        assert_ne!(a1, a2);
        assert_ne!(a2, a3);

        // Fee: 2 orchard + 6 notes + 300 new assets = 308 -> 1_540_000
        builder.add_orchard_output::<zip317::FeeRule>(
            Some(fvk.to_ovk(Scope::External)), recipient,
            Zatoshis::from_u64(98_460_000).unwrap(), AssetBase::zatoshi(), MemoBytes::empty(),
        ).unwrap();

        let tx = builder.mock_build(
            &TransparentSigningSet::new(), &[], &[SpendAuthorizingKey::from(&sk)],
            |_| true, &mut rng,
        ).unwrap().into_transaction();

        let ib = tx.issue_bundle().unwrap();
        assert_eq!(ib.actions().len(), 3);
        assert_eq!(ib.get_all_notes().len(), 6);
    }

    // -----------------------------------------------------------------
    // 3. Finalization
    // -----------------------------------------------------------------
    #[test]
    fn test_finalize_asset() {
        let mut rng = OsRng;
        let isk = IssueAuthKey::<orchard::issuance::auth::ZSASchnorr>::from_zip32_seed(
            &[4u8; 32], 1, 0).unwrap();
        let ik = IssueValidatingKey::from(&isk);
        let (note, fvk, sk, recipient, anchor, merkle_path) = create_test_note(10_000_000);
        let desc_hash = compute_asset_desc_hash(&NonEmpty::from_slice(b"FINAL").unwrap());
        let asset = AssetBase::custom(&AssetId::new_v0(&ik, &desc_hash));

        let mut zsa = ZsaBuilder::new(isk);
        zsa.add_issue_output(desc_hash, recipient, NoteValue::from_raw(500), true, &mut rng).unwrap();
        zsa.finalize_asset(&desc_hash).unwrap();

        let mut builder = Builder::new(TEST_NETWORK, nu7_height(), BuildConfig::Standard {
            sapling_anchor: Some(sapling::Anchor::empty_tree()),
            orchard_anchor: Some(anchor),
        });
        builder.set_zsa_builder(zsa);
        builder.add_orchard_spend::<zip317::FeeRule>(fvk.clone(), note, merkle_path).unwrap();
        builder.add_orchard_output::<zip317::FeeRule>(
            Some(fvk.to_ovk(Scope::External)), recipient,
            Zatoshis::from_u64(9_480_000).unwrap(), AssetBase::zatoshi(), MemoBytes::empty(),
        ).unwrap();

        let tx = builder.mock_build(
            &TransparentSigningSet::new(), &[], &[SpendAuthorizingKey::from(&sk)],
            |a| a == &asset, &mut rng,
        ).unwrap().into_transaction();

        assert!(tx.issue_bundle().unwrap().actions()[0].is_finalized());
    }

    // -----------------------------------------------------------------
    // 4. Subsequent issuance (same asset, two batches)
    // -----------------------------------------------------------------
    #[test]
    fn test_issuance_subsequent_batch() {
        let mut rng = OsRng;
        let isk = IssueAuthKey::<orchard::issuance::auth::ZSASchnorr>::from_zip32_seed(
            &[5u8; 32], 1, 0).unwrap();
        let ik = IssueValidatingKey::from(&isk);
        let (note, fvk, sk, recipient, anchor, merkle_path) = create_test_note(10_000_000);
        let desc_hash = compute_asset_desc_hash(&NonEmpty::from_slice(b"BATCH").unwrap());
        let asset = AssetBase::custom(&AssetId::new_v0(&ik, &desc_hash));

        let mut builder = Builder::new(TEST_NETWORK, nu7_height(), BuildConfig::Standard {
            sapling_anchor: Some(sapling::Anchor::empty_tree()),
            orchard_anchor: Some(anchor),
        });
        builder.add_orchard_spend::<zip317::FeeRule>(fvk.clone(), note, merkle_path).unwrap();

        builder.add_issue_output::<zip317::FeeRule>(
            &isk, desc_hash, recipient, NoteValue::from_raw(100), true).unwrap();
        builder.add_issue_output::<zip317::FeeRule>(
            &isk, desc_hash, recipient, NoteValue::from_raw(200), false).unwrap();

        // Fee: 2 orchard + 3 notes + 100 = 105 -> 525_000
        builder.add_orchard_output::<zip317::FeeRule>(
            Some(fvk.to_ovk(Scope::External)), recipient,
            Zatoshis::from_u64(9_475_000).unwrap(), AssetBase::zatoshi(), MemoBytes::empty(),
        ).unwrap();

        let tx = builder.mock_build(
            &TransparentSigningSet::new(), &[], &[SpendAuthorizingKey::from(&sk)],
            |a| a == &asset, &mut rng,
        ).unwrap().into_transaction();

        let ib = tx.issue_bundle().unwrap();
        assert_eq!(ib.actions().len(), 1);
        assert_eq!(ib.get_all_notes().len(), 3);
    }

    // -----------------------------------------------------------------
    // 5. Burn: verify add_burn is accepted (balance requires spending the same asset)
    // -----------------------------------------------------------------
    #[test]
    fn test_burn_custom_asset() {
        let isk = IssueAuthKey::<orchard::issuance::auth::ZSASchnorr>::from_zip32_seed(
            &[6u8; 32], 1, 0).unwrap();
        let ik = IssueValidatingKey::from(&isk);
        let desc_hash = compute_asset_desc_hash(&NonEmpty::from_slice(b"WETH").unwrap());
        let weth = AssetBase::custom(&AssetId::new_v0(&ik, &desc_hash));
        let (note, fvk, _sk, _recipient, anchor, merkle_path) = create_test_note(10_000_000);

        let mut builder = Builder::new(TEST_NETWORK, nu7_height(), BuildConfig::Standard {
            sapling_anchor: Some(sapling::Anchor::empty_tree()),
            orchard_anchor: Some(anchor),
        });
        builder.add_orchard_spend::<zip317::FeeRule>(fvk, note, merkle_path).unwrap();

        // add_burn accepts custom assets (not zatoshi)
        assert!(builder.add_burn::<zip317::FeeRule>(100, weth).is_ok());

        // add_burn rejects zatoshi
        assert!(builder.add_burn::<zip317::FeeRule>(100, AssetBase::zatoshi()).is_err());
    }

    // -----------------------------------------------------------------
    // 6. Full build: issuance produces valid tx with orchard bundle
    // -----------------------------------------------------------------
    #[test]
    fn test_build_with_issuance() {
        let mut rng = OsRng;
        let isk = IssueAuthKey::<orchard::issuance::auth::ZSASchnorr>::from_zip32_seed(
            &[7u8; 32], 1, 0).unwrap();
        let ik = IssueValidatingKey::from(&isk);
        let (note, fvk, sk, recipient, anchor, merkle_path) = create_test_note(10_000_000);
        let desc_hash = compute_asset_desc_hash(&NonEmpty::from_slice(b"BUILD").unwrap());
        let asset = AssetBase::custom(&AssetId::new_v0(&ik, &desc_hash));

        let mut zsa = ZsaBuilder::new(isk);
        zsa.add_issue_output(desc_hash, recipient, NoteValue::from_raw(1_000), true, &mut rng).unwrap();

        let mut builder = Builder::new(TEST_NETWORK, nu7_height(), BuildConfig::Standard {
            sapling_anchor: Some(sapling::Anchor::empty_tree()),
            orchard_anchor: Some(anchor),
        });
        builder.set_zsa_builder(zsa);
        builder.add_orchard_spend::<zip317::FeeRule>(fvk.clone(), note, merkle_path).unwrap();
        builder.add_orchard_output::<zip317::FeeRule>(
            Some(fvk.to_ovk(Scope::External)), recipient,
            Zatoshis::from_u64(9_480_000).unwrap(), AssetBase::zatoshi(), MemoBytes::empty(),
        ).unwrap();

        let result = builder.mock_build(
            &TransparentSigningSet::new(), &[], &[SpendAuthorizingKey::from(&sk)],
            |a| a == &asset, &mut rng,
        ).unwrap().into_transaction();

        let ob = result.orchard_bundle().unwrap();
        assert!(ob.as_zsa_bundle().actions().len() >= 2, "expected >=2 orchard actions");
        assert!(!result.issue_bundle().unwrap().get_all_notes().is_empty());
    }
}
