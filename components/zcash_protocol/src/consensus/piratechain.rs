//! Consensus parameters for the Pirate Chain network.
//!
//! Pirate Chain is a Zcash-derived chain that activated both Overwinter and
//! Sapling at block height 152,855 on its main network, and does not deploy
//! the Blossom-or-later network upgrades.

use super::{BlockHeight, BranchId, NetworkType, NetworkUpgrade, Parameters};

/// The network upgrades on the Pirate Chain in order of activation.
const PIRATECHAIN_UPGRADES_IN_ORDER: &[NetworkUpgrade] =
    &[NetworkUpgrade::Overwinter, NetworkUpgrade::Sapling];

/// Marker struct for the Pirate Chain main network.
#[derive(PartialEq, Copy, Clone, Debug)]
pub struct MainNetwork;

/// The Pirate Chain main network.
pub const PIRATECHAIN_MAIN_NETWORK: MainNetwork = MainNetwork;

impl Parameters for MainNetwork {
    fn network_type(&self) -> NetworkType {
        NetworkType::Pirate
    }

    fn upgrades_in_order(&self) -> &'static [NetworkUpgrade] {
        PIRATECHAIN_UPGRADES_IN_ORDER
    }

    fn branch_id(&self, nu: NetworkUpgrade) -> BranchId {
        match nu {
            NetworkUpgrade::Overwinter => BranchId::Overwinter,
            NetworkUpgrade::Sapling => BranchId::Sapling,
            _ => nu.branch_id(),
        }
    }

    fn activation_height(&self, nu: NetworkUpgrade) -> Option<BlockHeight> {
        match nu {
            NetworkUpgrade::Overwinter => Some(BlockHeight::from_u32(152_855)),
            NetworkUpgrade::Sapling => Some(BlockHeight::from_u32(152_855)),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{BlockHeight, BranchId, PIRATECHAIN_MAIN_NETWORK};

    #[test]
    fn piratechain_branch_ids() {
        assert_eq!(
            BranchId::for_height(&PIRATECHAIN_MAIN_NETWORK, BlockHeight::from_u32(152_854)),
            BranchId::Sprout
        );
        assert_eq!(
            BranchId::for_height(&PIRATECHAIN_MAIN_NETWORK, BlockHeight::from_u32(152_855)),
            BranchId::Sapling
        );
    }
}
