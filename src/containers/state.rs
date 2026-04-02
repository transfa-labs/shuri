use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
use libssz_types::{SszBitlist, SszList};

use crate::{
    chain::config::DEVNET_CONFIG,
    containers::{
        block::BlockHeader, checkpoint::Checkpoint, config::Config, validator::Validator,
    },
};

/// The main consensus state object.
#[derive(SszEncode, SszDecode, HashTreeRoot)]
pub struct State {
    /// The chain's configuration parameters
    pub config: Config,

    /// The current slot number
    pub slot: u64,

    /// The header of the most recent block
    pub latest_block_header: BlockHeader,

    /// The latest justified checkpoint
    pub latest_justified: Checkpoint,

    /// The latest finalized checkpoint
    pub latest_finalized: Checkpoint,

    /// A list of historical block root hashes
    pub historical_block_hashes: SszList<[u8; 32], { DEVNET_CONFIG.historical_roots_limit }>,

    /// A bitfield indicating which historical slots were justified.
    pub justified_slots: SszBitlist<{ DEVNET_CONFIG.historical_roots_limit }>,

    /// Registry of validators tracked by the state.
    pub validators: SszList<Validator, { DEVNET_CONFIG.validator_registry_limit }>,

    /// Roots of justified blocks.
    pub justification_roots: SszList<[u8; 32], { DEVNET_CONFIG.historical_roots_limit }>,

    /// A bitlist of validators who participated in justifications
    pub justification_validators: SszBitlist<
        { DEVNET_CONFIG.historical_roots_limit * DEVNET_CONFIG.validator_registry_limit },
    >,
}
