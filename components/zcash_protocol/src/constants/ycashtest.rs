//! Constants for the Ycash test network.

/// The Ycash coin type for YEC, as defined by [SLIP 44].
///
/// [SLIP 44]: https://github.com/satoshilabs/slips/blob/master/slip-0044.md
pub const COIN_TYPE: u32 = 347;

/// The HRP for a Bech32-encoded Ycash test network Sapling
/// [`ExtendedSpendingKey`].
///
/// Defined in [ZIP 32].
///
/// [`ExtendedSpendingKey`]: https://docs.rs/sapling-crypto/latest/sapling_crypto/zip32/struct.ExtendedSpendingKey.html
/// [ZIP 32]: https://github.com/zcash/zips/blob/main/zips/zip-0032.rst
pub const HRP_SAPLING_EXTENDED_SPENDING_KEY: &str = "secret-extended-key-main";

/// The HRP for a Bech32-encoded Ycash test network Sapling
/// [`ExtendedFullViewingKey`].
///
/// Defined in [ZIP 32].
///
/// [`ExtendedFullViewingKey`]: https://docs.rs/sapling-crypto/latest/sapling_crypto/zip32/struct.ExtendedFullViewingKey.html
/// [ZIP 32]: https://github.com/zcash/zips/blob/main/zips/zip-0032.rst
pub const HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY: &str = "zxviews";

/// The HRP for a Bech32-encoded Ycash test network Sapling
/// [`PaymentAddress`].
///
/// Defined in section 5.6.4 of the [Zcash Protocol Specification].
///
/// [`PaymentAddress`]: https://docs.rs/sapling-crypto/latest/sapling_crypto/struct.PaymentAddress.html
/// [Zcash Protocol Specification]: https://github.com/zcash/zips/blob/main/rendered/protocol/protocol.pdf
pub const HRP_SAPLING_PAYMENT_ADDRESS: &str = "ytestsapling";

/// The prefix for a Base58Check-encoded Ycash test network Sprout address.
///
/// Defined in the [Zcash Protocol Specification section 5.6.3][sproutpaymentaddrencoding].
///
/// [sproutpaymentaddrencoding]: https://zips.z.cash/protocol/protocol.pdf#sproutpaymentaddrencoding
pub const B58_SPROUT_ADDRESS_PREFIX: [u8; 2] = [0x16, 0x9a];

/// The prefix for a Base58Check-encoded DER-encoded Ycash test network [`SecretKey`].
///
/// [`SecretKey`]: https://docs.rs/secp256k1/latest/secp256k1/struct.SecretKey.html
pub const B58_SECRET_KEY_PREFIX: [u8; 1] = [0x80];

/// The prefix for a Base58Check-encoded Ycash test network [`PublicKeyHash`].
///
/// [`PublicKeyHash`]: https://docs.rs/zcash_transparent/latest/zcash_transparent/address/enum.TransparentAddress.html
pub const B58_PUBKEY_ADDRESS_PREFIX: [u8; 2] = [0x1c, 0x95];

/// The prefix for a Base58Check-encoded Ycash test network [`ScriptHash`].
///
/// [`ScriptHash`]: https://docs.rs/zcash_transparent/latest/zcash_transparent/address/enum.TransparentAddress.html
pub const B58_SCRIPT_ADDRESS_PREFIX: [u8; 2] = [0x1c, 0x2a];

/// The HRP for a Bech32m-encoded Ycash test network [ZIP 320] TEX address.
///
/// [ZIP 320]: https://zips.z.cash/zip-0320
pub const HRP_TEX_ADDRESS: &str = "textest";

/// The HRP for a Bech32m-encoded Ycash test network Unified Address.
///
/// Defined in [ZIP 316][zip-0316].
///
/// [zip-0316]: https://zips.z.cash/zip-0316
pub const HRP_UNIFIED_ADDRESS: &str = "utest";

/// The HRP for a Bech32m-encoded Ycash test network Unified FVK.
///
/// Defined in [ZIP 316][zip-0316].
///
/// [zip-0316]: https://zips.z.cash/zip-0316
pub const HRP_UNIFIED_FVK: &str = "uviewtest";

/// The HRP for a Bech32m-encoded Ycash test network Unified IVK.
///
/// Defined in [ZIP 316][zip-0316].
///
/// [zip-0316]: https://zips.z.cash/zip-0316
pub const HRP_UNIFIED_IVK: &str = "uivktest";
