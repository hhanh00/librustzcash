use crate::consensus::{Parameters, NetworkUpgrade, BlockHeight};
use crate::constants;

const YCASH_UPGRADES_IN_ORDER: &[NetworkUpgrade] =
    &[
        NetworkUpgrade::Overwinter,
        NetworkUpgrade::Sapling,
        NetworkUpgrade::Ycash,
        NetworkUpgrade::YBlossom,
        NetworkUpgrade::YHeartwood,
        NetworkUpgrade::YCanopy,
    ];

#[derive(PartialEq, Copy, Clone, Debug)]
pub struct MainNetwork;

impl Parameters for MainNetwork {
    fn upgrades_in_order(&self) -> &'static [NetworkUpgrade] { YCASH_UPGRADES_IN_ORDER }

    fn activation_height(&self, nu: NetworkUpgrade) -> Option<BlockHeight> {
        match nu {
            NetworkUpgrade::Overwinter => Some(BlockHeight(347_500)),
            NetworkUpgrade::Sapling => Some(BlockHeight(419_200)),
            NetworkUpgrade::Ycash => Some(BlockHeight(570_000)),
            NetworkUpgrade::Blossom => None,
            NetworkUpgrade::Heartwood => None,
            NetworkUpgrade::Canopy => None,
            NetworkUpgrade::YBlossom => Some(BlockHeight(1_100_000)),
            NetworkUpgrade::YHeartwood => Some(BlockHeight(1_100_003)),
            NetworkUpgrade::YCanopy => Some(BlockHeight(1_100_006)),
            #[cfg(feature = "zfuture")]
            NetworkUpgrade::ZFuture => None,
        }
    }

    fn coin_type(&self) -> u32 {
        347
    }

    fn hrp_sapling_extended_spending_key(&self) -> &str {
        constants::mainnet::HRP_SAPLING_EXTENDED_SPENDING_KEY
    }

    fn hrp_sapling_extended_full_viewing_key(&self) -> &str {
        constants::mainnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY
    }

    fn hrp_sapling_payment_address(&self) -> &str {
        "ys"
    }

    fn b58_pubkey_address_prefix(&self) -> [u8; 2] {
        [0x1c, 0x28]
    }

    fn b58_script_address_prefix(&self) -> [u8; 2] {
        [0x1c, 0x2c]
    }
}

#[derive(PartialEq, Copy, Clone, Debug)]
pub struct TestNetwork;

impl Parameters for TestNetwork {
    fn upgrades_in_order(&self) -> &'static [NetworkUpgrade] {
        YCASH_UPGRADES_IN_ORDER
    }

    fn activation_height(&self, nu: NetworkUpgrade) -> Option<BlockHeight> {
        match nu {
            NetworkUpgrade::Overwinter => Some(BlockHeight(207_500)),
            NetworkUpgrade::Sapling => Some(BlockHeight(280_000)),
            NetworkUpgrade::Ycash => Some(BlockHeight(510_248)),
            NetworkUpgrade::Blossom => None,
            NetworkUpgrade::Heartwood => None,
            NetworkUpgrade::Canopy => None,
            NetworkUpgrade::YBlossom => Some(BlockHeight(661_610)),
            NetworkUpgrade::YHeartwood => Some(BlockHeight(661_622)),
            NetworkUpgrade::YCanopy => Some(BlockHeight(661_634)),
            #[cfg(feature = "zfuture")]
            NetworkUpgrade::ZFuture => None,
        }
    }

    fn coin_type(&self) -> u32 {
        347
    }

    fn hrp_sapling_extended_spending_key(&self) -> &str {
        constants::mainnet::HRP_SAPLING_EXTENDED_SPENDING_KEY
    }

    fn hrp_sapling_extended_full_viewing_key(&self) -> &str {
        constants::mainnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY
    }

    fn hrp_sapling_payment_address(&self) -> &str {
        "ytestsapling"
    }

    fn b58_pubkey_address_prefix(&self) -> [u8; 2] {
        [0x1c, 0x95]
    }

    fn b58_script_address_prefix(&self) -> [u8; 2] {
        [0x1c, 0x2a]
    }
}
