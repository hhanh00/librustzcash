//! Consensus parameters for the Ycash networks.
//!
//! Ycash is a fork of Zcash activated at block height 570,000 on its main
//! network. It diverges from Zcash after Sapling activation, deploying its
//! own branch IDs from the fork activation onward, and it does not deploy the
//! NU5-or-later network upgrades.

use super::{BlockHeight, BranchId, NetworkType, NetworkUpgrade, Parameters};

/// The network upgrades on the Ycash chain in order of activation.
const YCASH_UPGRADES_IN_ORDER: &[NetworkUpgrade] = &[
    NetworkUpgrade::Overwinter,
    NetworkUpgrade::Sapling,
    NetworkUpgrade::Ycash,
    NetworkUpgrade::Blossom,
    NetworkUpgrade::Heartwood,
    NetworkUpgrade::Canopy,
];

/// Marker struct for the Ycash main network.
#[derive(PartialEq, Copy, Clone, Debug)]
pub struct MainNetwork;

/// The Ycash main network.
pub const YCASH_MAIN_NETWORK: MainNetwork = MainNetwork;

impl Parameters for MainNetwork {
    fn network_type(&self) -> NetworkType {
        NetworkType::Ycash
    }

    fn upgrades_in_order(&self) -> &'static [NetworkUpgrade] {
        YCASH_UPGRADES_IN_ORDER
    }

    fn branch_id(&self, nu: NetworkUpgrade) -> BranchId {
        match nu {
            NetworkUpgrade::Overwinter => BranchId::Overwinter,
            NetworkUpgrade::Sapling => BranchId::Sapling,
            NetworkUpgrade::Ycash => BranchId::Ycash,
            NetworkUpgrade::Blossom => BranchId::YBlossom,
            NetworkUpgrade::Heartwood => BranchId::YHeartwood,
            NetworkUpgrade::Canopy => BranchId::YCanopy,
            _ => nu.branch_id(),
        }
    }

    fn activation_height(&self, nu: NetworkUpgrade) -> Option<BlockHeight> {
        match nu {
            NetworkUpgrade::Overwinter => Some(BlockHeight::from_u32(347_500)),
            NetworkUpgrade::Sapling => Some(BlockHeight::from_u32(419_200)),
            NetworkUpgrade::Ycash => Some(BlockHeight::from_u32(570_000)),
            NetworkUpgrade::Blossom => Some(BlockHeight::from_u32(1_100_000)),
            NetworkUpgrade::Heartwood => Some(BlockHeight::from_u32(1_100_003)),
            NetworkUpgrade::Canopy => Some(BlockHeight::from_u32(1_100_006)),
            _ => None,
        }
    }
}

/// Marker struct for the Ycash test network.
#[derive(PartialEq, Copy, Clone, Debug)]
pub struct TestNetwork;

/// The Ycash test network.
pub const YCASH_TEST_NETWORK: TestNetwork = TestNetwork;

impl Parameters for TestNetwork {
    fn network_type(&self) -> NetworkType {
        NetworkType::YcashTest
    }

    fn upgrades_in_order(&self) -> &'static [NetworkUpgrade] {
        YCASH_UPGRADES_IN_ORDER
    }

    fn branch_id(&self, nu: NetworkUpgrade) -> BranchId {
        match nu {
            NetworkUpgrade::Overwinter => BranchId::Overwinter,
            NetworkUpgrade::Sapling => BranchId::Sapling,
            NetworkUpgrade::Ycash => BranchId::Ycash,
            NetworkUpgrade::Blossom => BranchId::YBlossom,
            NetworkUpgrade::Heartwood => BranchId::YHeartwood,
            NetworkUpgrade::Canopy => BranchId::YCanopy,
            _ => nu.branch_id(),
        }
    }

    fn activation_height(&self, nu: NetworkUpgrade) -> Option<BlockHeight> {
        match nu {
            NetworkUpgrade::Overwinter => Some(BlockHeight::from_u32(207_500)),
            NetworkUpgrade::Sapling => Some(BlockHeight::from_u32(280_000)),
            NetworkUpgrade::Ycash => Some(BlockHeight::from_u32(510_248)),
            NetworkUpgrade::Blossom => Some(BlockHeight::from_u32(661_610)),
            NetworkUpgrade::Heartwood => Some(BlockHeight::from_u32(661_622)),
            NetworkUpgrade::Canopy => Some(BlockHeight::from_u32(661_634)),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{BlockHeight, BranchId, Parameters, YCASH_MAIN_NETWORK, YCASH_TEST_NETWORK};

    #[test]
    fn ycash_main_branch_ids() {
        // Pre-fork epochs use the Zcash branch IDs.
        assert_eq!(
            BranchId::for_height(&YCASH_MAIN_NETWORK, BlockHeight::from_u32(400_000)),
            BranchId::Overwinter
        );
        assert_eq!(
            BranchId::for_height(&YCASH_MAIN_NETWORK, BlockHeight::from_u32(500_000)),
            BranchId::Sapling
        );
        // The fork epoch and its successors use the Ycash branch IDs.
        assert_eq!(
            BranchId::for_height(&YCASH_MAIN_NETWORK, BlockHeight::from_u32(600_000)),
            BranchId::Ycash
        );
        assert_eq!(
            BranchId::for_height(&YCASH_MAIN_NETWORK, BlockHeight::from_u32(1_100_001)),
            BranchId::YBlossom
        );
        assert_eq!(
            BranchId::for_height(&YCASH_MAIN_NETWORK, BlockHeight::from_u32(1_100_004)),
            BranchId::YHeartwood
        );
        assert_eq!(
            BranchId::for_height(&YCASH_MAIN_NETWORK, BlockHeight::from_u32(1_200_000)),
            BranchId::YCanopy
        );
    }

    #[test]
    fn ycash_test_branch_ids() {
        assert_eq!(
            BranchId::for_height(&YCASH_TEST_NETWORK, BlockHeight::from_u32(600_000)),
            BranchId::Ycash
        );
        assert_eq!(
            BranchId::for_height(&YCASH_TEST_NETWORK, BlockHeight::from_u32(700_000)),
            BranchId::YCanopy
        );
    }

    #[test]
    fn ycash_has_no_nu5() {
        for nu in [
            super::NetworkUpgrade::Nu5,
            super::NetworkUpgrade::Nu6,
            super::NetworkUpgrade::Nu6_1,
            super::NetworkUpgrade::Nu6_2,
            super::NetworkUpgrade::Nu6_3,
        ] {
            assert!(!YCASH_MAIN_NETWORK.is_nu_active(nu, BlockHeight::from_u32(2_000_000)));
        }
    }
}
