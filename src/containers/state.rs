use std::collections::HashMap;

use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
use libssz_merkle::{HashTreeRoot, Sha2Hasher};
use libssz_types::{SszBitlist, SszList};

use crate::{
    chain::config::DEVNET_CONFIG,
    containers::{
        block::{AttestationList, Block, BlockBody, BlockHeader},
        checkpoint::Checkpoint,
        config::Config,
        slot::Slot,
        validator::Validator,
    },
};

pub type Validators = SszList<Validator, { DEVNET_CONFIG.validator_registry_limit }>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("target slot must be in the future")]
    InvalidTargetSlot { current: u64, target: u64 },

    #[error("block slot mismatch: current={current} target={target}")]
    BlockSlotMismatch { current: u64, target: u64 },

    #[error("block (slot={block}) is older than latest header (slot={latest_header})")]
    BlockTooOld { block: u64, latest_header: u64 },

    #[error("incorrect block proposer: block={block} state={state}")]
    IncorrectProposer { block: u64, state: u64 },

    #[error("block parent root mismatch")]
    ParentRootMismatch,

    #[error("validator registry is empty")]
    EmptyValidatorRegistry,

    #[error("list is over capacity: {0}")]
    OverCapacity(#[source] libssz_types::TypeError),

    #[error("out of bounds: index {index}, length {length}")]
    OutOfBounds { index: usize, length: usize },

    #[error("invalid index: {0}")]
    InvalidIndex(#[source] libssz_types::IndexError),

    #[error("invalid block state root")]
    InvalidBlockStateRoot,
}

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
    pub validators: Validators,

    /// Roots of justified blocks.
    pub justification_roots: SszList<[u8; 32], { DEVNET_CONFIG.historical_roots_limit }>,

    /// A bitlist of validators who participated in justifications
    pub justification_validators: SszBitlist<
        { DEVNET_CONFIG.historical_roots_limit * DEVNET_CONFIG.validator_registry_limit },
    >,
}

impl State {
    /// Generate a genesis state with empty history and proper initial values
    pub fn from_genesis(genesis_time: u64, validators: Validators) -> Self {
        Self {
            config: Config { genesis_time },
            slot: 0,
            latest_block_header: BlockHeader {
                body_root: BlockBody::default().hash_tree_root(&Sha2Hasher),
                ..Default::default()
            },
            latest_justified: Default::default(),
            latest_finalized: Default::default(),
            historical_block_hashes: Default::default(),
            justified_slots: Default::default(),
            validators,
            justification_roots: Default::default(),
            justification_validators: Default::default(),
        }
    }

    /// Advance the state through empty slots up to, but not including, target_slot.
    pub fn process_slots(&mut self, target_slot: u64) -> Result<(), Error> {
        if self.slot >= target_slot {
            return Err(Error::InvalidTargetSlot {
                current: self.slot,
                target: target_slot,
            });
        }

        if self.latest_block_header.state_root == [0u8; 32] {
            self.latest_block_header.state_root = self.hash_tree_root(&Sha2Hasher);
        }

        self.slot = target_slot;

        Ok(())
    }

    /// Validate the block header and update header-linked state.
    pub fn process_block_header(&mut self, block: &Block) -> Result<(), Error> {
        if self.slot != block.slot {
            return Err(Error::BlockSlotMismatch {
                current: self.slot,
                target: block.slot,
            });
        }

        if block.slot <= self.latest_block_header.slot {
            return Err(Error::BlockTooOld {
                block: block.slot,
                latest_header: self.latest_block_header.slot,
            });
        }

        if self.validators.is_empty() {
            return Err(Error::EmptyValidatorRegistry);
        }

        let proposer_index = self.slot % self.validators.len() as u64;

        if proposer_index != block.proposer_index {
            return Err(Error::IncorrectProposer {
                block: block.proposer_index,
                state: proposer_index,
            });
        }

        let parent_root = self.latest_block_header.hash_tree_root(&Sha2Hasher);

        if block.parent_root != parent_root {
            return Err(Error::ParentRootMismatch);
        }

        // Special case: first block after genesis.
        if self.latest_block_header.slot == 0 {
            self.latest_justified.root = parent_root;
            self.latest_finalized.root = parent_root;
        };

        self.historical_block_hashes
            .push(parent_root)
            .map_err(Error::OverCapacity)?;

        self.justified_slots
            .push(self.latest_block_header.slot == 0)
            .map_err(Error::OverCapacity)?;

        let num_empty_slots = block.slot - self.latest_block_header.slot - 1;

        // If there were empty slots between parent and this block, fill them.
        for _ in 0..num_empty_slots {
            self.historical_block_hashes
                .push([0u8; 32])
                .map_err(Error::OverCapacity)?;
            self.justified_slots
                .push(false)
                .map_err(Error::OverCapacity)?;
        }

        self.latest_block_header = BlockHeader {
            slot: block.slot,
            proposer_index: block.proposer_index,
            parent_root: block.parent_root,
            state_root: [0u8; 32],
            body_root: block.body.hash_tree_root(&Sha2Hasher),
        };

        Ok(())
    }

    /// Apply full block processing including header and body
    pub fn process_block(&mut self, block: &Block) -> Result<(), Error> {
        self.process_block_header(block)?;
        self.process_attestations(&block.body.attestations)
    }

    /// Apply attestations and update justification/finalization according to the
    /// Lean Consensus 3SF-mini rules.
    ///
    /// The simplified consensus mechanism:
    /// 1. Processes each attestation
    /// 2. Updates justified status for target checkpoints
    /// 3. Applies finalization rules based on justified status
    pub fn process_attestations(&mut self, attestations: &AttestationList) -> Result<(), Error> {
        // Restructuring the flattened vote list such that each block root
        // is linked to the votes of all validators for that block.
        let mut justifications: HashMap<[u8; 32], Vec<bool>> = HashMap::new();
        let validator_count = self.validators.len();
        for (i, root) in self.justification_roots.iter().enumerate() {
            let start = i * validator_count;
            let end = (i + 1) * validator_count;
            let votes = (start..end).map(|idx| {
                self.justification_validators.get(idx) == Some(true)
            }).collect();
            justifications.insert(*root, votes);
        }

        for attestation in attestations {
            let source = &attestation.data.source;
            let target = &attestation.data.target;

            // We ignore attestations whose source is not already justified,
            // or whose target is not in the history, or whose target is
            // not a valid justifiable slot.

            let should_skip =
                // Source slot must be justified
                self.justified_slots.get(source.slot as usize) != Some(true)
                
                // Target slot must not be already justified
                || self.justified_slots.get(target.slot as usize) == Some(true)
                
                // Source root must match the state's historical block hashes
                || Some(&source.root) != self.historical_block_hashes.get(source.slot as usize)

                // Target root must match the state's historical block hashes
                || Some(&target.root) != self.historical_block_hashes.get(target.slot as usize)

                // Target slot must be after the source slot
                || target.slot <= source.slot

                // Target slot must be justifiable after the latest finalized slot
                || !target.slot.is_justifiable_after(self.latest_finalized.slot);

            if should_skip {
                continue;
            }

            let justification = justifications
                .entry(target.root)
                .or_insert(vec![false; validator_count]);
            let validator_id = attestation.validator_id as usize;
            if justification.get(validator_id) != Some(&true) {
                if validator_id >= justification.len() {
                    return Err(Error::OutOfBounds {
                        index: validator_id,
                        length: justification.len(),
                    });
                }
                justification[validator_id] = true;
            }

            let count = justification.iter().filter(|i| **i).count();

            if 3 * count >= 2 * validator_count {
                self.latest_justified = target.clone();
                self.justified_slots
                    .set(target.slot as usize, true)
                    .map_err(Error::InvalidIndex)?;
                justifications.remove(&target.root);

                // Finalization: if the target is the next valid justifiable hash
                // after the source
                if !(source.slot + 1..target.slot)
                    .any(|slot| slot.is_justifiable_after(self.latest_finalized.slot))
                {
                    self.latest_finalized = source.clone();
                }
            }
        }

        let (roots, votes): (Vec<[u8; 32]>, Vec<Vec<bool>>) = {
            let mut entries = justifications.into_iter().collect::<Vec<(_, _)>>();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            entries.into_iter().unzip()
        };

        self.justification_roots = SszList::try_from(roots).map_err(Error::OverCapacity)?;

        let votes: Vec<bool> = votes.into_iter().flatten().collect();
        self.justification_validators = SszBitlist::try_from(votes).map_err(Error::OverCapacity)?;

        Ok(())
    }

    /// Apply the complete state transition function for a block
    ///
    /// This methods represents the full state transition function:
    /// 1. Validate signatures if required
    /// 2. Process slots up to the block's slot
    /// 3. Process the block header and body
    /// 4. Validate the computed state root
    pub fn state_transition(&mut self, block: &Block) -> Result<(), Error> {
        self.process_slots(block.slot)?;
        self.process_block(block)?;

        if self.hash_tree_root(&Sha2Hasher) != block.state_root {
            return Err(Error::InvalidBlockStateRoot);
        }

        Ok(())
    }
}
