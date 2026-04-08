use std::collections::HashMap;

use libssz_merkle::{HashTreeRoot, Sha2Hasher};

use crate::{
    chain::config::SECONDS_PER_SLOT,
    containers::{Block, Checkpoint, Config, SignedAttestation, SignedBlockWithAttestation, State},
};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("state root mismatch, expected {expected:?} got {actual:?}")]
    StateRootMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },

    #[error("unknown block: {root:?}")]
    UnknownBlock { root: [u8; 32] },

    #[error("unknown state: {root:?}")]
    UnknownState { root: [u8; 32] },

    #[error("source ({source_slot}) must be older than target ({target_slot})")]
    SourceMustBeOlder { source_slot: u64, target_slot: u64 },

    #[error("checkpoint slot mismatch")]
    CheckpointSlotMismatch { expected: u64, actual: u64 },

    #[error("attestation too far in future")]
    TooFarInFuture { slot: u64 },
}

/// Forkchoice store tracking chain state and validator attestation
///
/// This is the "local view" that a node uses to run LMD GHOST.
/// It contains:
///
/// - which blocks and states are known,
/// - which checkpoints are justified and finalized,
/// - which block is currently considered the head,
/// - and, for each validator, their latest attestation that should
///   the forkchoice.
///
/// The Store is updated whenever:
/// - a new block is processed,
/// - an attestation is received (via a block or gossip),
/// - an interval tick occurs (activating new attestations),
/// - or when the head is recomputed
#[derive(Debug)]
pub struct Store {
    /// Curren time in intervals since genesis.
    pub time: u64,

    /// Chain configuration parameters.
    pub config: Config,

    /// Root of the current canonical chain head block.
    pub head: [u8; 32],

    /// Root of the current safe target for attestation.
    pub safe_target: [u8; 32],

    /// Highest slot justified checkpoint known to the store.
    pub latest_justified: Checkpoint,

    /// Highest slot finalized checkpoint known to the store.
    pub latest_finalized: Checkpoint,

    /// Mapping from block root to Block objects.
    pub blocks: HashMap<[u8; 32], Block>,

    /// Mapping from the state root to the State objects.
    pub states: HashMap<[u8; 32], State>,

    /// Latest signed attestation by validator that have been processed.
    pub latest_known_attestations: HashMap<u64, SignedAttestation>,

    /// Latest signed attestation by validator that are pending processing.
    pub latest_new_attestations: HashMap<u64, SignedAttestation>,
}

impl Store {
    /// Initialize forkchoice store from an anchor state and block
    pub fn get_forckchoice_store(state: State, anchor_block: Block) -> Result<Self, Error> {
        if anchor_block.state_root != state.hash_tree_root(&Sha2Hasher) {
            return Err(Error::StateRootMismatch {
                expected: anchor_block.state_root,
                actual: state.hash_tree_root(&Sha2Hasher),
            });
        }

        let anchor_root = anchor_block.hash_tree_root(&Sha2Hasher);
        let anchor_checkpoint = Checkpoint {
            root: anchor_root,
            slot: anchor_block.slot,
        };
        Ok(Self {
            time: anchor_block.slot * SECONDS_PER_SLOT,
            config: Config {
                genesis_time: state.config.genesis_time,
            },
            head: anchor_root,
            safe_target: anchor_root,
            latest_justified: anchor_checkpoint.clone(),
            latest_finalized: anchor_checkpoint,
            blocks: HashMap::from([(anchor_root, anchor_block)]),
            states: HashMap::from([(anchor_root, state)]),
            latest_known_attestations: HashMap::new(),
            latest_new_attestations: HashMap::new(),
        })
    }

    /// Validate incoming attestation before processing.
    ///
    /// Ensures the vote respects the basic laws of time
    /// and topology:
    /// 1. The block voted for must exist in our store
    /// 2. A vote cannot span backwards in time (source > target).
    /// 3. A vote cannot be for a future slot.
    pub fn validate_attestation(
        &self,
        signed_attestation: &SignedAttestation,
    ) -> Result<(), Error> {
        let data = &signed_attestation.message.data;

        let source_block = self
            .blocks
            .get(&data.source.root)
            .ok_or(Error::UnknownBlock {
                root: data.source.root,
            })?;

        let target_block = self
            .blocks
            .get(&data.target.root)
            .ok_or(Error::UnknownBlock {
                root: data.target.root,
            })?;

        self.blocks
            .get(&data.head.root)
            .ok_or(Error::UnknownBlock {
                root: data.head.root,
            })?;

        if data.source.slot > data.target.slot {
            return Err(Error::SourceMustBeOlder {
                source_slot: data.source.slot,
                target_slot: data.target.slot,
            });
        }

        if source_block.slot != data.source.slot {
            return Err(Error::CheckpointSlotMismatch {
                expected: source_block.slot,
                actual: data.source.slot,
            });
        }

        if target_block.slot != data.target.slot {
            return Err(Error::CheckpointSlotMismatch {
                expected: target_block.slot,
                actual: data.target.slot,
            });
        }

        let current_slot = self.time / SECONDS_PER_SLOT;

        if data.slot > current_slot + 1 {
            return Err(Error::TooFarInFuture { slot: current_slot });
        }

        Ok(())
    }

    /// Process a new attestation and place it into the attestation stage
    fn on_attestation(
        &mut self,
        signed_attestation: SignedAttestation,
        is_from_block: bool,
    ) -> Result<(), Error> {
        self.validate_attestation(&signed_attestation)?;
        let validator_id = signed_attestation.message.validator_id;
        let attestation_slot = signed_attestation.message.data.slot;

        if is_from_block {
            // On-chain attestation processing
            // These are historical attestations from other validators included
            // by the proposer.

            let latest_known = self.latest_known_attestations.get(&validator_id);
            if latest_known.is_none_or(|v| v.message.data.slot < attestation_slot) {
                self.latest_known_attestations
                    .insert(validator_id, signed_attestation);
            }

            let existing_new = self.latest_new_attestations.get(&validator_id);

            if existing_new.is_some_and(|v| v.message.data.slot <= attestation_slot) {
                self.latest_new_attestations.remove(&validator_id);
            }
        } else {
            // Network gossip attestation processing
            // These are attestations received via the gossip network
            let time_slots = self.time / SECONDS_PER_SLOT;
            if attestation_slot > time_slots {
                return Err(Error::TooFarInFuture {
                    slot: attestation_slot,
                });
            }

            let latest_new = self.latest_new_attestations.get(&validator_id);

            if latest_new.is_none_or(|v| v.message.data.slot < attestation_slot) {
                self.latest_new_attestations
                    .insert(validator_id, signed_attestation);
            }
        }

        Ok(())
    }

    /// Process a new block and update teh forkchoice state.
    ///
    /// This method integrates a block into the forkchoice store by:
    /// 1. Validating the block's parent exists
    /// 2. Computing the post-state via the state transition function
    /// 3. Processing attestations included in the block body (on-chain)
    /// 4. Updating the forkchoice head
    /// 5. Processing the proposer's attestation (as if gossiped)
    pub fn on_block(
        &mut self,
        signed_block_with_attestations: &SignedBlockWithAttestation,
    ) -> Result<(), Error> {
        let block = &signed_block_with_attestations.message.block;

        if self.blocks.contains_key(&block.hash_tree_root(&Sha2Hasher)) {
            return Ok(());
        }

        let parent_state = self
            .states
            .get(&block.parent_root)
            .ok_or(Error::UnknownState {
                root: block.parent_root,
            })?;
        let post_state = parent_state.state_transition(block)

        Ok(())
    }
}
