// SPDX-License-Identifier: CC0-1.0

//! Bitcoin consensus parameters.
//!
//! This module provides a predefined set of parameters for different Bitcoin
//! chains (such as mainnet, testnet, testnet4).
//!

use crate::network::Network;
#[cfg(doc)]
use crate::pow::CompactTarget;
use crate::pow::Target;

/// Parameters that influence chain consensus.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct Params {
    /// Network for which parameters are valid.
    pub network: Network,
    /// Time when BIP16 becomes active.
    pub bip16_time: u32,
    /// Block height at which BIP34 becomes active.
    pub bip34_height: u32,
    /// Block height at which BIP65 becomes active.
    pub bip65_height: u32,
    /// Block height at which BIP66 becomes active.
    pub bip66_height: u32,
    /// Minimum blocks including miner confirmation of the total of 2016 blocks in a retargeting period,
    /// (nPowTargetTimespan / nPowTargetSpacing) which is also used for BIP9 deployments.
    /// Examples: 1916 for 95%, 1512 for testchains.
    pub rule_change_activation_threshold: u32,
    /// Number of blocks with the same set of rules.
    pub miner_confirmation_window: u32,
    /// Proof of work limit value. It contains the lowest possible difficulty.
    #[deprecated(since = "0.32.0", note = "field renamed to max_attainable_target")]
    pub pow_limit: Target,
    /// The maximum **attainable** target value for these params.
    ///
    /// Not all target values are attainable because consensus code uses the compact format to
    /// represent targets (see [`CompactTarget`]).
    ///
    /// Note that this value differs from Bitcoin Core's powLimit field in that this value is
    /// attainable, but Bitcoin Core's is not. Specifically, because targets in Bitcoin are always
    /// rounded to the nearest float expressible in "compact form", not all targets are attainable.
    /// Still, this should not affect consensus as the only place where the non-compact form of
    /// this is used in Bitcoin Core's consensus algorithm is in comparison and there are no
    /// compact-expressible values between Bitcoin Core's and the limit expressed here.
    pub max_attainable_target: Target,
    /// Expected amount of time to mine one block.
    pub pow_target_spacing: u64,
    /// Difficulty recalculation interval.
    pub pow_target_timespan: u64,
    /// Determines whether minimal difficulty may be used for blocks or not.
    pub allow_min_difficulty_blocks: bool,
    /// Determines whether retargeting is disabled for this network or not.
    pub no_pow_retargeting: bool,
}

/// The mainnet parameters.
///
/// Use this for a static reference e.g., `&params::MAINNET`.
///
/// For more on static vs const see The Rust Reference [using-statics-or-consts] section.
///
/// [using-statics-or-consts]: <https://doc.rust-lang.org/reference/items/static-items.html#using-statics-or-consts>
pub static MAINNET: Params = Params::MAINNET;
/// The testnet4 parameters (Litecoin's only testnet).
pub static TESTNET4: Params = Params::TESTNET4;
/// The signet parameters (kept for upstream compat).
pub static SIGNET: Params = Params::SIGNET;
/// The regtest parameters.
pub static REGTEST: Params = Params::REGTEST;

#[allow(deprecated)] // For `pow_limit`.
impl Params {
    /// The mainnet parameters (alias for `Params::MAINNET`).
    pub const BITCOIN: Params = Params::MAINNET;

    /// The mainnet (litecoin) parameters.
    ///
    /// BIP16 P2SH activated at block 218579 on Litecoin; the timestamp field is unused but kept
    /// for upstream compatibility (set to a value comfortably after the height-based activation).
    pub const MAINNET: Params = Params {
        network: Network::Bitcoin,
        bip16_time: 1333238400, // Litecoin enforces BIP16 by height (block 218579), not timestamp.
        bip34_height: 710000,
        bip65_height: 918684,
        bip66_height: 811879,
        rule_change_activation_threshold: 6048, // 75% of 8064-block window
        miner_confirmation_window: 8064,
        pow_limit: Target::MAX_ATTAINABLE_MAINNET,
        max_attainable_target: Target::MAX_ATTAINABLE_MAINNET,
        pow_target_spacing: 150,                // 2.5 minutes.
        pow_target_timespan: 150 * 2016,        // 3.5 days.
        allow_min_difficulty_blocks: false,
        no_pow_retargeting: false,
    };

    /// The testnet4 (Litecoin testnet) parameters.
    pub const TESTNET4: Params = Params {
        network: Network::Testnet4,
        bip16_time: 1333238400, // Litecoin testnet activated BIP16 at height 0.
        bip34_height: 76,
        bip65_height: 76,
        bip66_height: 76,
        rule_change_activation_threshold: 1512, // 75% of 2016-block window
        miner_confirmation_window: 2016,
        pow_limit: Target::MAX_ATTAINABLE_TESTNET,
        max_attainable_target: Target::MAX_ATTAINABLE_TESTNET,
        pow_target_spacing: 150,
        pow_target_timespan: 150 * 2016,
        allow_min_difficulty_blocks: true,
        no_pow_retargeting: false,
    };

    /// The signet parameters.
    pub const SIGNET: Params = Params {
        network: Network::Signet,
        bip16_time: 1333238400, // Apr 1 2012
        bip34_height: 1,
        bip65_height: 1,
        bip66_height: 1,
        rule_change_activation_threshold: 1916, // 95%
        miner_confirmation_window: 2016,
        pow_limit: Target::MAX_ATTAINABLE_SIGNET,
        max_attainable_target: Target::MAX_ATTAINABLE_SIGNET,
        pow_target_spacing: 10 * 60,            // 10 minutes.
        pow_target_timespan: 14 * 24 * 60 * 60, // 2 weeks.
        allow_min_difficulty_blocks: false,
        no_pow_retargeting: false,
    };

    /// The regtest parameters.
    pub const REGTEST: Params = Params {
        network: Network::Regtest,
        bip16_time: 1333238400,  // Apr 1 2012
        bip34_height: 100000000, // not activated on regtest
        bip65_height: 1351,
        bip66_height: 1251,                    // used only in rpc tests
        rule_change_activation_threshold: 108, // 75%
        miner_confirmation_window: 144,
        pow_limit: Target::MAX_ATTAINABLE_REGTEST,
        max_attainable_target: Target::MAX_ATTAINABLE_REGTEST,
        pow_target_spacing: 150,                // 2.5 minutes (Litecoin).
        pow_target_timespan: 150 * 2016,
        allow_min_difficulty_blocks: true,
        no_pow_retargeting: true,
    };

    /// Creates parameters set for the given network.
    pub const fn new(network: Network) -> Self {
        match network {
            Network::Bitcoin => Params::MAINNET,
            Network::Testnet4 => Params::TESTNET4,
            Network::Signet => Params::SIGNET,
            Network::Regtest => Params::REGTEST,
        }
    }

    /// Calculates the number of blocks between difficulty adjustments.
    pub fn difficulty_adjustment_interval(&self) -> u64 {
        self.pow_target_timespan / self.pow_target_spacing
    }
}

impl From<Network> for Params {
    fn from(value: Network) -> Self { Self::new(value) }
}

impl From<&Network> for Params {
    fn from(value: &Network) -> Self { Self::new(*value) }
}

impl From<Network> for &'static Params {
    fn from(value: Network) -> Self { value.params() }
}

impl From<&Network> for &'static Params {
    fn from(value: &Network) -> Self { value.params() }
}

impl AsRef<Params> for Params {
    fn as_ref(&self) -> &Params { self }
}

impl AsRef<Params> for Network {
    fn as_ref(&self) -> &Params { Self::params(*self) }
}
