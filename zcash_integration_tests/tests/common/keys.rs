//! Key derivation helpers for integration tests.

use orchard::{
    keys::{FullViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
    Address as OrchardAddress,
};
use transparent::{
    address::TransparentAddress,
    keys::{AccountPrivKey, IncomingViewingKey, NonHardenedChildIndex},
};
use zcash_address::ToAddress;
use zcash_protocol::consensus::NetworkType;

/// Creates a transparent account from a seed.
/// Returns the account private key, the p2pkh address, and the secret key for signing.
pub fn make_transparent_account(
    seed: &[u8],
) -> (
    AccountPrivKey,
    TransparentAddress,
    secp256k1::SecretKey,
) {
    let tsk = AccountPrivKey::from_seed(
        &zcash_protocol::consensus::TEST_NETWORK,
        seed,
        zip32::AccountId::ZERO,
    )
    .expect("valid transparent key seed");
    let (_taddr, address_index) = tsk
        .to_account_pubkey()
        .derive_external_ivk()
        .expect("ivk derivation")
        .default_address();
    let t_sk = tsk
        .derive_external_secret_key(address_index)
        .expect("secret key derivation");
    let p2pkh_addr = TransparentAddress::from_pubkey(
        &t_sk.public_key(&secp256k1::Secp256k1::signing_only()),
    );
    (tsk, p2pkh_addr, t_sk)
}

/// Encodes a transparent address as a string for the given network type.
pub fn encode_transparent_address(addr: &TransparentAddress, net: NetworkType) -> String {
    addr.to_zcash_address(net).encode()
}

/// Creates an Orchard spending key, full viewing key, and address from a seed.
pub fn make_orchard_account(seed: &[u8; 32]) -> (SpendingKey, FullViewingKey, OrchardAddress) {
    let sk = SpendingKey::from_zip32_seed(seed, 1, zip32::AccountId::ZERO)
        .expect("valid orchard key seed");
    let fvk = FullViewingKey::from(&sk);
    let addr = fvk.address_at(0u32, Scope::External);
    (sk, fvk, addr)
}

/// Returns the spend authorizing key from a spending key.
pub fn orchard_sak(sk: &SpendingKey) -> SpendAuthorizingKey {
    SpendAuthorizingKey::from(sk)
}
