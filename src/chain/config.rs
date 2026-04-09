/// Number of intervals per slot for forkchoice processing.
pub const INTERVALS_PER_SLOT: u64 = 4;

/// The fixed duration of a single slot in seconds.
pub const SECONDS_PER_SLOT: u64 = 4;

/// Seconds per forkchoice processing interval.
pub const SECONDS_PER_INTERVAL: u64 = SECONDS_PER_SLOT / INTERVALS_PER_SLOT;

/// The number of slots to lookback for justification.
pub const JUSTIFICATION_LOOKBACK_SLOTS: u64 = 3;

/// The maximum number of historical block roots to store in the state.
///
/// With a 4-second slot, this corresponds to a history
/// of approximately 12.1 days.
pub const HISTORICAL_ROOTS_LIMIT: usize = 2usize.pow(18);

/// The maximum number of validators that can be in the registry.
pub const VALIDATOR_REGISTRY_LIMIT: usize = 2usize.pow(12);

#[allow(dead_code)]
pub struct ChainConfig {
    pub seconds_per_slot: u64,
    pub justification_lookback_slots: u64,
    pub historical_roots_limit: usize,
    pub validator_registry_limit: usize,
}

pub const DEVNET_CONFIG: ChainConfig = ChainConfig {
    seconds_per_slot: SECONDS_PER_SLOT,
    justification_lookback_slots: JUSTIFICATION_LOOKBACK_SLOTS,
    historical_roots_limit: HISTORICAL_ROOTS_LIMIT,
    validator_registry_limit: VALIDATOR_REGISTRY_LIMIT,
};
