use crate::consensus::{Parameters, NetworkUpgrade, BlockHeight};
use crate::constants;

#[derive(PartialEq, Copy, Clone, Debug)]
pub struct MainNetwork;

impl Parameters for MainNetwork {
    fn activation_height(&self, nu: NetworkUpgrade) -> Option<BlockHeight> {
        match nu {
            NetworkUpgrade::Overwinter => Some(BlockHeight(347_500)),
            NetworkUpgrade::Sapling => Some(BlockHeight(419_200)),
            NetworkUpgrade::Ycash => Some(BlockHeight(570_000)),
            NetworkUpgrade::Blossom => None,
            NetworkUpgrade::Heartwood => None,
            NetworkUpgrade::Canopy => None,
            NetworkUpgrade::YBlossom => None,
            NetworkUpgrade::YHeartwood => None,
            NetworkUpgrade::YCanopy => None,
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
    fn activation_height(&self, nu: NetworkUpgrade) -> Option<BlockHeight> {
        match nu {
            NetworkUpgrade::Overwinter => Some(BlockHeight(347_500)),
            NetworkUpgrade::Sapling => Some(BlockHeight(419_200)),
            NetworkUpgrade::Ycash => Some(BlockHeight(510_248)),
            NetworkUpgrade::Blossom => None,
            NetworkUpgrade::Heartwood => None,
            NetworkUpgrade::Canopy => None,
            NetworkUpgrade::YBlossom => Some(BlockHeight(661_100)),
            NetworkUpgrade::YHeartwood => Some(BlockHeight(661_112)),
            NetworkUpgrade::YCanopy => Some(BlockHeight(661_124)),
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
