use std::fmt;

use zcash_primitives::{
    consensus::{self, BlockHeight},
    memo::MemoBytes,
    transaction::{
        components::{
            amount::{BalanceError, NonNegativeAmount},
            OutPoint,
        },
        fees::{transparent, FeeRule},
    },
};
use zcash_protocol::{PoolType, ShieldedProtocol};

pub(crate) mod common;
pub mod fixed;
#[cfg(feature = "orchard")]
pub mod orchard;
pub mod sapling;
pub mod standard;
pub mod zip317;

/// `ChangeValue` represents either a proposed change output to a shielded pool
/// (with an optional change memo), or if the "transparent-inputs" feature is
/// enabled, an ephemeral output to the transparent pool.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChangeValue(ChangeValueInner);

#[derive(Clone, Debug, PartialEq, Eq)]
enum ChangeValueInner {
    Shielded {
        protocol: ShieldedProtocol,
        value: NonNegativeAmount,
        memo: Option<MemoBytes>,
    },
    #[cfg(feature = "transparent-inputs")]
    EphemeralTransparent { value: NonNegativeAmount },
}

impl ChangeValue {
    /// Constructs a new ephemeral transparent output value.
    #[cfg(feature = "transparent-inputs")]
    pub fn ephemeral_transparent(value: NonNegativeAmount) -> Self {
        Self(ChangeValueInner::EphemeralTransparent { value })
    }

    /// Constructs a new change value that will be created as a shielded output.
    pub fn shielded(
        protocol: ShieldedProtocol,
        value: NonNegativeAmount,
        memo: Option<MemoBytes>,
    ) -> Self {
        Self(ChangeValueInner::Shielded {
            protocol,
            value,
            memo,
        })
    }

    /// Constructs a new change value that will be created as a Sapling output.
    pub fn sapling(value: NonNegativeAmount, memo: Option<MemoBytes>) -> Self {
        Self::shielded(ShieldedProtocol::Sapling, value, memo)
    }

    /// Constructs a new change value that will be created as an Orchard output.
    #[cfg(feature = "orchard")]
    pub fn orchard(value: NonNegativeAmount, memo: Option<MemoBytes>) -> Self {
        Self::shielded(ShieldedProtocol::Orchard, value, memo)
    }

    /// Returns the pool to which the change or ephemeral output should be sent.
    pub fn output_pool(&self) -> PoolType {
        match &self.0 {
            ChangeValueInner::Shielded { protocol, .. } => PoolType::Shielded(*protocol),
            #[cfg(feature = "transparent-inputs")]
            ChangeValueInner::EphemeralTransparent { .. } => PoolType::Transparent,
        }
    }

    /// Returns the value of the change or ephemeral output to be created, in zatoshis.
    pub fn value(&self) -> NonNegativeAmount {
        match &self.0 {
            ChangeValueInner::Shielded { value, .. } => *value,
            #[cfg(feature = "transparent-inputs")]
            ChangeValueInner::EphemeralTransparent { value } => *value,
        }
    }

    /// Returns the memo to be associated with the output.
    pub fn memo(&self) -> Option<&MemoBytes> {
        match &self.0 {
            ChangeValueInner::Shielded { memo, .. } => memo.as_ref(),
            #[cfg(feature = "transparent-inputs")]
            ChangeValueInner::EphemeralTransparent { .. } => None,
        }
    }

    /// Whether this is to be an ephemeral output.
    #[cfg_attr(
        not(feature = "transparent-inputs"),
        doc = "This is always false because the `transparent-inputs` feature is
               not enabled."
    )]
    pub fn is_ephemeral(&self) -> bool {
        match &self.0 {
            ChangeValueInner::Shielded { .. } => false,
            #[cfg(feature = "transparent-inputs")]
            ChangeValueInner::EphemeralTransparent { .. } => true,
        }
    }
}

/// The amount of change and fees required to make a transaction's inputs and
/// outputs balance under a specific fee rule, as computed by a particular
/// [`ChangeStrategy`] that is aware of that rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionBalance {
    proposed_change: Vec<ChangeValue>,
    fee_required: NonNegativeAmount,

    // A cache for the sum of proposed change and fee; we compute it on construction anyway, so we
    // cache the resulting value.
    total: NonNegativeAmount,
}

impl TransactionBalance {
    /// Constructs a new balance from its constituent parts.
    pub fn new(
        proposed_change: Vec<ChangeValue>,
        fee_required: NonNegativeAmount,
    ) -> Result<Self, ()> {
        let total = proposed_change
            .iter()
            .map(|c| c.value())
            .chain(Some(fee_required).into_iter())
            .sum::<Option<NonNegativeAmount>>()
            .ok_or(())?;

        Ok(Self {
            proposed_change,
            fee_required,
            total,
        })
    }

    /// The change values proposed by the [`ChangeStrategy`] that computed this balance.
    pub fn proposed_change(&self) -> &[ChangeValue] {
        &self.proposed_change
    }

    /// Returns the fee computed for the transaction, assuming that the suggested
    /// change outputs are added to the transaction.
    pub fn fee_required(&self) -> NonNegativeAmount {
        self.fee_required
    }

    /// Returns the sum of the proposed change outputs and the required fee.
    pub fn total(&self) -> NonNegativeAmount {
        self.total
    }
}

/// Errors that can occur in computing suggested change and/or fees.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChangeError<E, NoteRefT> {
    /// Insufficient inputs were provided to change selection to fund the
    /// required outputs and fees.
    InsufficientFunds {
        /// The total of the inputs provided to change selection
        available: NonNegativeAmount,
        /// The total amount of input value required to fund the requested outputs,
        /// including the required fees.
        required: NonNegativeAmount,
    },
    /// Some of the inputs provided to the transaction have value less than the
    /// marginal fee, and could not be determined to have any economic value in
    /// the context of this input selection.
    ///
    /// This determination is potentially conservative in the sense that inputs
    /// with value less than or equal to the marginal fee might be excluded, even
    /// though in practice they would not cause the fee to increase. Inputs with
    /// value greater than the marginal fee will never be excluded.
    ///
    /// The ordering of the inputs in each list is unspecified.
    DustInputs {
        /// The outpoints for transparent inputs that could not be determined to
        /// have economic value in the context of this input selection.
        transparent: Vec<OutPoint>,
        /// The identifiers for Sapling inputs that could not be determined to
        /// have economic value in the context of this input selection.
        sapling: Vec<NoteRefT>,
        /// The identifiers for Orchard inputs that could not be determined to
        /// have economic value in the context of this input selection.
        #[cfg(feature = "orchard")]
        orchard: Vec<NoteRefT>,
    },
    /// An error occurred that was specific to the change selection strategy in use.
    StrategyError(E),
    /// The proposed bundle structure would violate bundle type construction rules.
    BundleError(&'static str),
}

impl<E, NoteRefT> ChangeError<E, NoteRefT> {
    pub(crate) fn map<E0, F: FnOnce(E) -> E0>(self, f: F) -> ChangeError<E0, NoteRefT> {
        match self {
            ChangeError::InsufficientFunds {
                available,
                required,
            } => ChangeError::InsufficientFunds {
                available,
                required,
            },
            ChangeError::DustInputs {
                transparent,
                sapling,
                #[cfg(feature = "orchard")]
                orchard,
            } => ChangeError::DustInputs {
                transparent,
                sapling,
                #[cfg(feature = "orchard")]
                orchard,
            },
            ChangeError::StrategyError(e) => ChangeError::StrategyError(f(e)),
            ChangeError::BundleError(e) => ChangeError::BundleError(e),
        }
    }
}

impl<CE: fmt::Display, N: fmt::Display> fmt::Display for ChangeError<CE, N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self {
            ChangeError::InsufficientFunds {
                available,
                required,
            } => write!(
                f,
                "Insufficient funds: required {} zatoshis, but only {} zatoshis were available.",
                u64::from(*required),
                u64::from(*available)
            ),
            ChangeError::DustInputs {
                transparent,
                sapling,
                #[cfg(feature = "orchard")]
                orchard,
            } => {
                #[cfg(feature = "orchard")]
                let orchard_len = orchard.len();
                #[cfg(not(feature = "orchard"))]
                let orchard_len = 0;

                // we can't encode the UA to its string representation because we
                // don't have network parameters here
                write!(
                    f,
                    "Insufficient funds: {} dust inputs were present, but would cost more to spend than they are worth.",
                    transparent.len() + sapling.len() + orchard_len,
                )
            }
            ChangeError::StrategyError(err) => {
                write!(f, "{}", err)
            }
            ChangeError::BundleError(err) => {
                write!(
                    f,
                    "The proposed transaction structure violates bundle type constraints: {}",
                    err
                )
            }
        }
    }
}

impl<NoteRefT> From<BalanceError> for ChangeError<BalanceError, NoteRefT> {
    fn from(err: BalanceError) -> ChangeError<BalanceError, NoteRefT> {
        ChangeError::StrategyError(err)
    }
}

/// An enumeration of actions to take when a transaction would potentially create dust
/// outputs (outputs that are likely to be without economic value due to fee rules).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DustAction {
    /// Do not allow creation of dust outputs; instead, require that additional inputs be provided.
    Reject,
    /// Explicitly allow the creation of dust change amounts greater than the specified value.
    AllowDustChange,
    /// Allow dust amounts to be added to the transaction fee.
    AddDustToFee,
}

/// A policy describing how a [`ChangeStrategy`] should treat potentially dust-valued change
/// outputs (outputs that are likely to be without economic value due to fee rules).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DustOutputPolicy {
    action: DustAction,
    dust_threshold: Option<NonNegativeAmount>,
}

impl DustOutputPolicy {
    /// Constructs a new dust output policy.
    ///
    /// A dust policy created with `None` as the dust threshold will delegate determination
    /// of the dust threshold to the change strategy that is evaluating the strategy; this
    /// is recommended, but an explicit value (including zero) may be provided to explicitly
    /// override the determination of the change strategy.
    pub fn new(action: DustAction, dust_threshold: Option<NonNegativeAmount>) -> Self {
        Self {
            action,
            dust_threshold,
        }
    }

    /// Returns the action to take in the event that a dust change amount would be produced.
    pub fn action(&self) -> DustAction {
        self.action
    }
    /// Returns a value that will be used to override the dust determination logic of the
    /// change policy, if any.
    pub fn dust_threshold(&self) -> Option<NonNegativeAmount> {
        self.dust_threshold
    }
}

impl Default for DustOutputPolicy {
    fn default() -> Self {
        DustOutputPolicy::new(DustAction::Reject, None)
    }
}

/// `EphemeralParameters` can be used to specify variations on how balance
/// and fees are computed that are relevant to transactions using ephemeral
/// transparent outputs.
#[cfg(feature = "transparent-inputs")]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EphemeralParameters {
    ignore_change_memo: bool,
    ephemeral_input_amount: Option<NonNegativeAmount>,
    ephemeral_output_amount: Option<NonNegativeAmount>,
}

#[cfg(feature = "transparent-inputs")]
impl EphemeralParameters {
    /// Returns an `EphemeralParameters` with the following parameters:
    ///
    /// * `ignore_change_memo`: `true` if the change memo should be
    ///   ignored for the purpose of deciding whether there will be a
    ///   change output.
    /// * `ephemeral_input_amount`: specifies that there will be an
    ///   additional P2PKH input of the given amount.
    /// * `ephemeral_output_amount`: specifies that there will be an
    ///   additional P2PKH output of the given amount.
    pub fn new(
        ignore_change_memo: bool,
        ephemeral_input_amount: Option<NonNegativeAmount>,
        ephemeral_output_amount: Option<NonNegativeAmount>,
    ) -> Self {
        Self {
            ignore_change_memo,
            ephemeral_input_amount,
            ephemeral_output_amount,
        }
    }

    pub fn ignore_change_memo(&self) -> bool {
        self.ignore_change_memo
    }
    pub fn ephemeral_input_amount(&self) -> Option<NonNegativeAmount> {
        self.ephemeral_input_amount
    }
    pub fn ephemeral_output_amount(&self) -> Option<NonNegativeAmount> {
        self.ephemeral_output_amount
    }
}

/// A trait that represents the ability to compute the suggested change and fees that must be paid
/// by a transaction having a specified set of inputs and outputs.
pub trait ChangeStrategy {
    type FeeRule: FeeRule;
    type Error;

    /// Returns the fee rule that this change strategy will respect when performing
    /// balance computations.
    fn fee_rule(&self) -> &Self::FeeRule;

    /// Computes the totals of inputs, suggested change amounts, and fees given the
    /// provided inputs and outputs being used to construct a transaction.
    ///
    /// The fee computed as part of this operation should take into account the prospective
    /// change outputs recommended by this operation. If insufficient funds are available to
    /// supply the requested outputs and required fees, implementations should return
    /// [`ChangeError::InsufficientFunds`].
    ///
    /// If the inputs include notes or UTXOs that are not economic to spend in the context
    /// of this input selection, a [`ChangeError::DustInputs`] error can be returned
    /// indicating inputs that should be removed from the selection (all of which will
    /// have value less than or equal to the marginal fee). The caller should order the
    /// inputs from most to least preferred to spend within each pool, so that the most
    /// preferred ones are less likely to be indicated to remove.
    ///
    #[cfg_attr(
        feature = "transparent-inputs",
        doc = "`ephemeral_parameters` can be used to specify variations on how balance
               and fees are computed that are relevant to transactions using ephemeral
               transparent outputs; see [`EphemeralParameters::new`]."
    )]
    #[allow(clippy::too_many_arguments)]
    fn compute_balance<P: consensus::Parameters, NoteRefT: Clone>(
        &self,
        params: &P,
        target_height: BlockHeight,
        transparent_inputs: &[impl transparent::InputView],
        transparent_outputs: &[impl transparent::OutputView],
        sapling: &impl sapling::BundleView<NoteRefT>,
        #[cfg(feature = "orchard")] orchard: &impl orchard::BundleView<NoteRefT>,
        dust_output_policy: &DustOutputPolicy,
        #[cfg(feature = "transparent-inputs")] ephemeral_parameters: &EphemeralParameters,
    ) -> Result<TransactionBalance, ChangeError<Self::Error, NoteRefT>>;
}

#[cfg(test)]
pub(crate) mod tests {
    use zcash_primitives::transaction::{
        components::{
            amount::NonNegativeAmount,
            transparent::{OutPoint, TxOut},
        },
        fees::transparent,
    };

    use super::sapling;

    #[derive(Debug)]
    pub(crate) struct TestTransparentInput {
        pub outpoint: OutPoint,
        pub coin: TxOut,
    }

    impl transparent::InputView for TestTransparentInput {
        fn outpoint(&self) -> &OutPoint {
            &self.outpoint
        }
        fn coin(&self) -> &TxOut {
            &self.coin
        }
    }

    pub(crate) struct TestSaplingInput {
        pub note_id: u32,
        pub value: NonNegativeAmount,
    }

    impl sapling::InputView<u32> for TestSaplingInput {
        fn note_id(&self) -> &u32 {
            &self.note_id
        }
        fn value(&self) -> NonNegativeAmount {
            self.value
        }
    }
}
