use std::collections::HashMap;

use libssz_merkle::{HashTreeRoot, Sha2Hasher};

use crate::{
    chain::config::SECONDS_PER_SLOT,
    containers::{
        Block, Checkpoint, Config, SignedAttestation, SignedBlockWithAttestation, State, block,
        state,
    },
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

    #[error("index out of range")]
    IndexOutOfRange,

    #[error(transparent)]
    StateTransition(#[from] state::Error),

    #[error(transparent)]
    SignatureVerification(#[from] block::Error),
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

    /// Process a new block and update the forkchoice state.
    ///
    /// This method integrates a block into the forkchoice store by:
    /// 1. Validating the block's parent exists
    /// 2. Computing the post-state via the state transition function
    /// 3. Processing attestations included in the block body (on-chain)
    /// 4. Updating the forkchoice head
    /// 5. Processing the proposer's attestation (as if gossiped)
    pub fn on_block(
        &mut self,
        signed_block_with_attestations: SignedBlockWithAttestation,
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

        signed_block_with_attestations.verify_signatures(parent_state)?;

        let mut post_state = parent_state.clone();
        post_state.state_transition(block)?;

        self.latest_justified.slot =
            if post_state.latest_justified.slot > self.latest_justified.slot {
                post_state.latest_justified.slot
            } else {
                self.latest_justified.slot
            };
        self.latest_finalized.slot =
            if post_state.latest_finalized.slot > self.latest_finalized.slot {
                post_state.latest_finalized.slot
            } else {
                self.latest_finalized.slot
            };

        let block_root = block.parent_root;
        self.states
            .extend(HashMap::from([(block_root, post_state)]));

        let signatures = signed_block_with_attestations.signature;
        let proposer_attestation = signed_block_with_attestations.message.proposer_attestation;

        self.blocks.extend(HashMap::from([(
            block_root,
            signed_block_with_attestations.message.block,
        )]));

        let attestations = {
            let block = self.blocks.get(&block_root).expect("block inserted");
            block.body.attestations.clone()
        };
        let attestation_count = attestations.len();
        let proposer_signature = signatures
            .get(attestation_count)
            .ok_or(Error::IndexOutOfRange)?
            .clone();

        for (attestation, signature) in attestations.into_iter().zip(signatures.into_iter()) {
            self.on_attestation(
                SignedAttestation {
                    message: attestation,
                    signature,
                },
                true,
            )?;
        }

        self.update_head();

        self.on_attestation(
            SignedAttestation {
                message: proposer_attestation,
                signature: proposer_signature,
            },
            false,
        )?;

        Ok(())
    }

    /// Walk the block tree to the LMD GHOST rule.
    ///
    /// The walk starts from a chosen root.
    /// At each fork, the child subtree with the highest weight
    /// is taken. The process stops when a leaf is reached.
    /// That leaf is the chosen head.
    ///
    /// Weights are derived from validator votes. When two branches
    /// have equal weight, the one with the lexicographically larger
    /// hash is chosen to break the tie.
    fn compute_lmd_ghost_head(
        &self,
        start_root: [u8; 32],
        attestations: &HashMap<u64, SignedAttestation>,
        min_score: u64,
    ) -> [u8; 32] {
        // If the starting point is not defined, choose the
        // earliest known block.
        let start_root = if start_root == [0u8; 32] {
            self.blocks
                .iter()
                .min_by_key(|(_, value)| value.slot)
                .map(|(key, _)| key)
                .expect("blocks should not be empty")
        } else {
            &start_root
        };

        let start_block = self
            .blocks
            .get(start_root)
            .expect("start_root retrieved from blocks");

        let mut weights: HashMap<[u8; 32], u64> = HashMap::new();

        // Derive the weights.
        //
        // Weights are derived as follows:
        // - Each validator contributes its full weight to its most
        //   recent head vote.
        // - The weight of that vote also flows to every ancestor of
        //   the voted block.
        // - The weight of a subtree is the sum of all contributions
        //   inside it.
        //
        // For every vote, follow the chosen head upwards through
        // its ancestors. Each visited block accumulates one unit
        // of weight from that validator.
        for attestation in attestations.values() {
            let mut current_root = attestation.message.data.head.root;
            while let Some(block) = self.blocks.get(&current_root)
                && block.slot > start_block.slot
            {
                *weights.entry(current_root).or_default() += 1;
                current_root = block.parent_root;
            }
        }

        let mut children_map: HashMap<[u8; 32], Vec<[u8; 32]>> = HashMap::new();

        for (root, block) in self.blocks.iter() {
            // Skip blocks without parents (e.g. genesis or orphans)
            if block.parent_root == [0u8; 32] {
                continue;
            }

            // Prune branches early if they lack sufficient weight
            if min_score > 0 && weights.get(root).is_some_and(|v| *v < min_score) {
                continue;
            }

            children_map
                .entry(block.parent_root)
                .or_default()
                .push(*root);
        }

        let mut head = start_root;

        // Descend the tree, choosing the heaviest branch at every fork
        while let Some(children) = children_map.get(head)
            && !children.is_empty()
        {
            head = children
                .iter()
                .max_by_key(|x| (weights.get(*x).unwrap_or(&0), *x))
                .expect("children is not empty");
        }

        *head
    }

    /// Compute updated store with new canonical head
    ///
    /// Selects canonical head by walking the tree from
    /// the justified root, choosing the heaviest child
    /// at each fork based on attestation weights.
    pub fn update_head(&mut self) {
        self.head = self.compute_lmd_ghost_head(
            self.latest_justified.root,
            &self.latest_known_attestations,
            0,
        );
    }
}
