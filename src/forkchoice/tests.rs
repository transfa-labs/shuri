use std::collections::HashMap;

use libssz_merkle::{HashTreeRoot, Sha2Hasher};
use libssz_types::{SszBitlist, SszList, SszVector};

use crate::{
    containers::{
        Attestation, AttestationData, Block, BlockBody, BlockHeader, Checkpoint, Config,
        SignedAttestation, State, Validator, block, state::Validators,
    },
    forkchoice::store::{self, Store},
};

fn prefixed_bytes(prefix: &str) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[..prefix.len()].copy_from_slice(prefix.as_bytes());
    bytes
}

fn sample_state() -> State {
    let block_header = BlockHeader {
        slot: 0,
        proposer_index: 0,
        parent_root: [0u8; 32],
        state_root: prefixed_bytes("state"),
        body_root: prefixed_bytes("body"),
    };

    let validators: Validators = SszList::try_from(
        (0..10)
            .map(|_| Validator {
                pubkey: [0u8; 52],
                index: 0,
            })
            .collect::<Vec<Validator>>(),
    )
    .unwrap();

    State {
        config: Config { genesis_time: 1000 },
        slot: 0,
        latest_block_header: block_header,
        latest_justified: Checkpoint {
            root: prefixed_bytes("genesis"),
            slot: 0,
        },
        latest_finalized: Checkpoint {
            root: prefixed_bytes("genesis"),
            slot: 0,
        },
        historical_block_hashes: SszList::new(),
        justified_slots: SszBitlist::new(),
        justification_roots: SszList::new(),
        justification_validators: SszBitlist::new(),
        validators,
    }
}

fn sample_store() -> Store {
    let mut state = sample_state();
    let genesis_block = Block {
        slot: 0,
        proposer_index: 0,
        parent_root: [0u8; 32],
        state_root: state.hash_tree_root(&Sha2Hasher),
        body: block::BlockBody {
            attestations: SszList::new(),
        },
    };
    let genesis_hash = genesis_block.hash_tree_root(&Sha2Hasher);
    let genesis_header = BlockHeader {
        slot: genesis_block.slot,
        proposer_index: genesis_block.proposer_index,
        parent_root: genesis_block.parent_root,
        state_root: genesis_block.state_root,
        body_root: genesis_block.body.hash_tree_root(&Sha2Hasher),
    };

    let finalized = Checkpoint {
        root: genesis_hash,
        slot: 0,
    };
    state.latest_justified = finalized.clone();
    state.latest_finalized = finalized.clone();
    state.latest_block_header = genesis_header;

    Store {
        time: 100,
        config: Config { genesis_time: 1000 },
        head: genesis_hash,
        safe_target: genesis_hash,
        latest_justified: finalized.clone(),
        latest_finalized: finalized.clone(),
        blocks: HashMap::from([(genesis_hash, genesis_block)]),
        states: HashMap::from([(genesis_hash, state)]),
        latest_known_attestations: HashMap::new(),
        latest_new_attestations: HashMap::new(),
    }
}

fn build_signed_attestation(
    validator_id: u64,
    slot: u64,
    head: Checkpoint,
    source: Checkpoint,
    target: Checkpoint,
) -> SignedAttestation {
    SignedAttestation {
        message: Attestation {
            validator_id,
            data: AttestationData {
                slot,
                head,
                target,
                source,
            },
        },
        signature: SszVector::try_from(vec![0u8; 3116]).unwrap(),
    }
}

// --- Test validator block production

#[test]
fn test_produce_block_basic() {
    let mut store = sample_store();
    let (block_root, _signatures) = store.produce_block_with_signature(1, 1).unwrap();
    let block = store.blocks.get(&block_root).unwrap();
    assert_eq!(block_root, block.hash_tree_root(&Sha2Hasher));
    assert_eq!(block.slot, 1);
    assert_eq!(block.proposer_index, 1);
    assert_eq!(block.parent_root, store.head);
    assert_ne!(block.state_root, [0u8; 32]);
    assert!(store.states.contains_key(&block_root));
}

#[test]
fn test_produce_block_unauthorized_proposer() {
    let mut store = sample_store();
    assert!(matches!(
        store.produce_block_with_signature(1, 2),
        Err(store::Error::ValidatorIsNotProposer { index: 2, slot: 1 })
    ))
}

#[test]
fn test_produce_block_with_attestations() {
    let mut store = sample_store();
    let head_block = store.blocks.get(&store.head).unwrap();
    store.latest_known_attestations.insert(
        5,
        build_signed_attestation(
            5,
            head_block.slot,
            Checkpoint {
                root: store.head,
                slot: head_block.slot,
            },
            store.latest_justified.clone(),
            store.get_attestation_target().unwrap(),
        ),
    );
    store.latest_known_attestations.insert(
        6,
        build_signed_attestation(
            6,
            head_block.slot,
            Checkpoint {
                root: store.head,
                slot: head_block.slot,
            },
            store.latest_justified.clone(),
            store.get_attestation_target().unwrap(),
        ),
    );
    let slot = 2;
    let validator_idx = 2;

    let (block_hash, _signatures) = store
        .produce_block_with_signature(slot, validator_idx)
        .unwrap();

    let block = store.blocks.get(&block_hash).unwrap();
    // Block should include attestations from available attestations
    assert!(!block.body.attestations.is_empty());
    assert_eq!(block.slot, slot);
    assert_eq!(block.proposer_index, validator_idx);
    assert_ne!(block.state_root, [0u8; 32]);
}

#[test]
fn test_produce_block_sequential_slots() {
    let mut store = sample_store();
    let (block1_hash, _sigs) = store.produce_block_with_signature(1, 1).unwrap();
    let block1 = store.blocks.get(&block1_hash).unwrap();

    // Verify first block is properly created
    assert_eq!(block1.slot, 1);
    assert_eq!(block1.proposer_index, 1);
    assert!(store.states.contains_key(&block1_hash));

    // Produce block for slot 2 (will build on genesis due to forkchoice)
    let (block2_hash, _sigs) = store.produce_block_with_signature(2, 2).unwrap();
    let block2 = store.blocks.get(&block2_hash).unwrap();
    assert_eq!(block2.slot, 2);
    assert_eq!(block2.proposer_index, 2);
    assert!(store.blocks.contains_key(&store.head));
}

#[test]
fn test_produce_block_empty_attestations() {
    let mut store = sample_store();
    store.latest_known_attestations.clear();

    let (block_hash, _sigs) = store.produce_block_with_signature(3, 3).unwrap();
    let block = store.blocks.get(&block_hash).unwrap();

    // Should produce valid block with empty attestations
    assert_eq!(block.body.attestations.len(), 0);
    assert_eq!(block.slot, 3);
    assert_eq!(block.proposer_index, 3);
    assert_ne!(block.state_root, [0u8; 32]);
}

#[test]
fn test_produce_block_consistency() {
    let mut store = sample_store();
    let head_block = store.blocks.get(&store.head).unwrap();
    store.latest_known_attestations.insert(
        7,
        build_signed_attestation(
            7,
            head_block.slot,
            Checkpoint {
                root: store.head,
                slot: head_block.slot,
            },
            store.latest_justified.clone(),
            store.get_attestation_target().unwrap(),
        ),
    );

    let (block_hash, _sigs) = store.produce_block_with_signature(4, 4).unwrap();
    let block = store.blocks.get(&block_hash).unwrap();
    let state = store.states.get(&block_hash).unwrap();
    assert_eq!(state.hash_tree_root(&Sha2Hasher), block.state_root);
}

// --- Test validator attestation production

#[test]
fn test_produce_attestation_basic() {
    let store = sample_store();
    let validator_index = 5;
    let slot = 1;
    let validator = Validator {
        index: validator_index,
        pubkey: [0u8; 52],
    };
    let attestation_data = store.produce_attestation_data(slot).unwrap();
    let attestation = Attestation {
        validator_id: validator.index,
        data: attestation_data,
    };
    assert_eq!(attestation.validator_id, validator_index);
    assert_eq!(attestation.data.slot, slot);
    assert_eq!(attestation.data.source, store.latest_justified);
}

#[test]
fn test_produce_attestation_head_reference() {
    let mut store = sample_store();
    let validator_index = 8;
    let slot = 2;
    let validator = Validator {
        index: validator_index,
        pubkey: [0u8; 52],
    };
    let attestation_data = store.produce_attestation_data(slot).unwrap();
    let attestation = Attestation {
        validator_id: validator.index,
        data: attestation_data,
    };
    let expected_head_root = store.get_proposal_head(2).unwrap();
    // Head checkpoint should reference the current proposal head
    assert_eq!(attestation.data.head.root, expected_head_root);

    let head_block = store.blocks.get(&expected_head_root).unwrap();
    // Head slot should match the block's slot
    assert_eq!(attestation.data.head.slot, head_block.slot);
}

#[test]
fn test_produce_attestation_target_calculation() {
    let store = sample_store();
    let validator_index = 9;
    let slot = 3;
    let validator = Validator {
        index: validator_index,
        pubkey: [0u8; 52],
    };
    let attestation_data = store.produce_attestation_data(slot).unwrap();
    let attestation = Attestation {
        validator_id: validator.index,
        data: attestation_data,
    };
    let expected_target = store.get_attestation_target().unwrap();
    assert_eq!(attestation.data.target.root, expected_target.root);
    assert_eq!(attestation.data.target.slot, expected_target.slot);
}

#[test]
fn test_produce_attestation_different_validators() {
    let store = sample_store();
    let slot = 4;
    let mut attestations = Vec::new();

    // All validators should produce consistent attestations
    // for the same slot
    for validator_idx in 0..5 {
        let validator = Validator {
            pubkey: [0u8; 52],
            index: validator_idx,
        };

        let attestation_data = store.produce_attestation_data(slot).unwrap();
        let attestation = Attestation {
            validator_id: validator.index,
            data: attestation_data,
        };
        assert_eq!(attestation.validator_id, validator_idx);
        assert_eq!(attestation.data.slot, slot);
        attestations.push(attestation);
    }
    let first_attestation = attestations.first().unwrap();

    // All attestations should have same head, target, and source
    for attestation in &attestations[1..] {
        assert_eq!(attestation.data.head.root, first_attestation.data.head.root);
        assert_eq!(attestation.data.head.slot, first_attestation.data.head.slot);
        assert_eq!(
            attestation.data.target.root,
            first_attestation.data.target.root
        );
        assert_eq!(
            attestation.data.target.slot,
            first_attestation.data.target.slot
        );
        assert_eq!(
            attestation.data.source.root,
            first_attestation.data.source.root
        );
        assert_eq!(
            attestation.data.source.slot,
            first_attestation.data.source.slot
        );
    }
}

#[test]
fn test_produce_attestation_sequential_slots() {
    let store = sample_store();
    let validator_idx = 3;
    let validator = Validator {
        pubkey: [0u8; 52],
        index: validator_idx,
    };
    let attestation_data1 = store.produce_attestation_data(1).unwrap();
    let attestation1 = Attestation {
        validator_id: validator.index,
        data: attestation_data1,
    };
    let attestation_data2 = store.produce_attestation_data(2).unwrap();
    let attestation2 = Attestation {
        validator_id: validator.index,
        data: attestation_data2,
    };
    assert_eq!(attestation1.data.slot, 1);
    assert_eq!(attestation2.data.slot, 2);

    // Both should use the same source (latest justified doesn't change)
    assert_eq!(attestation1.data.source, attestation2.data.source);
    assert_eq!(attestation1.data.source, store.latest_justified);
}

#[test]
fn test_produce_attestation_justification_consistency() {
    let store = sample_store();
    let validator_index = 2;
    let slot = 5;
    let validator = Validator {
        index: validator_index,
        pubkey: [0u8; 52],
    };
    let attestation_data = store.produce_attestation_data(slot).unwrap();
    let attestation = Attestation {
        validator_id: validator.index,
        data: attestation_data,
    };

    // Source must be the latest justified checkpoint from store
    assert_eq!(attestation.data.source.root, store.latest_justified.root);
    assert_eq!(attestation.data.source.slot, store.latest_justified.slot);

    // Source checkpoint should exist in blocks
    assert!(store.blocks.contains_key(&attestation.data.source.root));
}

// --- Test integration between block production and attestations.

#[test]
fn test_block_production_then_attestation() {
    let mut store = sample_store();
    let proposer_slot = 1;
    let proposer_index = 1;
    // Proposer produces block for slot 1
    store
        .produce_block_with_signature(proposer_slot, proposer_index)
        .unwrap();

    // Update store state after block production
    store.update_head().unwrap();

    // Other validator creates attestation for slot 2
    let attestor_slot = 2;
    let attestor_idx = 7;
    let validator = Validator {
        pubkey: [0u8; 52],
        index: attestor_idx,
    };
    let attestation_data = store.produce_attestation_data(attestor_slot).unwrap();
    let attestation = Attestation {
        validator_id: validator.index,
        data: attestation_data,
    };

    // Attestation should reference the new block as head (if it became head)
    assert_eq!(attestation.validator_id, attestor_idx);
    assert_eq!(attestation.data.slot, attestor_slot);

    // The attestation should be consistent with current forkchoice state
    assert_eq!(attestation.data.source, store.latest_justified);
}

#[test]
fn test_mutiple_validators_coordination() {
    let mut store = sample_store();

    // Validator 1 produces block for slot 1
    let (block1_hash, _sigs) = store.produce_block_with_signature(1, 1).unwrap();

    let mut attestations = Vec::new();

    // Validators 2-5 create attestations for slot 2
    // These will be based on the current forkchoice head (genesis)
    for i in 2..6 {
        let validator = Validator {
            pubkey: [0u8; 52],
            index: i,
        };
        let attestation_data = store.produce_attestation_data(2).unwrap();
        let attestation = Attestation {
            validator_id: validator.index,
            data: attestation_data,
        };
        attestations.push(attestation);
    }

    // All attestations should be consistent
    let first_attestation = attestations.first().unwrap();
    for attestation in &attestations[1..] {
        assert_eq!(attestation.data.head.root, first_attestation.data.head.root);
        assert_eq!(attestation.data.head.slot, first_attestation.data.head.slot);
        assert_eq!(
            attestation.data.target.root,
            first_attestation.data.target.root
        );
        assert_eq!(
            attestation.data.target.slot,
            first_attestation.data.target.slot
        );
        assert_eq!(
            attestation.data.source.root,
            first_attestation.data.source.root
        );
        assert_eq!(
            attestation.data.source.slot,
            first_attestation.data.source.slot
        );
    }

    // Validator 2 produces next block for slot 2
    // After processing block1, head should be block1
    // (forkchoice walks the tree). So block2 will build
    // on blocks
    let (block2_hash, _sigs) = store.produce_block_with_signature(2, 2).unwrap();
    let block2 = store.blocks.get(&block2_hash).unwrap();

    assert_eq!(block2.slot, 2);
    assert_eq!(block2.proposer_index, 2);
    assert!(store.blocks.contains_key(&block1_hash));
    assert!(store.blocks.contains_key(&block2_hash));

    // block1 builds on genesis, block2 builds on block1 (current head)
    // Get the original genesis hash from the store's blocks
    let block1 = store.blocks.get(&block1_hash).unwrap();
    let genesis_hash = store
        .blocks
        .iter()
        .filter(|(_, v)| v.slot == 0)
        .map(|(k, _)| *k)
        .min()
        .unwrap();
    assert_eq!(block1.parent_root, genesis_hash);
    assert_eq!(block2.parent_root, block1_hash);
}

#[test]
fn test_validator_edge_cases() {
    let mut store = sample_store();
    // Test with validator index equal to number validators - 1
    let max_validator = 9;
    let slot = 9;

    let (block_hash, _sigs) = store
        .produce_block_with_signature(slot, max_validator)
        .unwrap();
    let block = store.blocks.get(&block_hash).unwrap();
    assert_eq!(block.proposer_index, max_validator);

    // Should be able to produce attestation
    let validator = Validator {
        pubkey: [0u8; 52],
        index: max_validator,
    };
    let attestation_data = store.produce_attestation_data(10).unwrap();
    let attestation = Attestation {
        validator_id: validator.index,
        data: attestation_data,
    };

    assert_eq!(attestation.validator_id, max_validator);
}

#[test]
fn test_validator_operations_empty_store() {
    let config = Config { genesis_time: 1000 };
    let genesis_body = BlockBody {
        attestations: SszList::new(),
    };
    let validators: Validators = SszList::try_from(
        (0..3)
            .map(|_| Validator {
                pubkey: [0u8; 52],
                index: 0,
            })
            .collect::<Vec<Validator>>(),
    )
    .unwrap();
    let mut state = State {
        config: config.clone(),
        slot: 0,
        latest_block_header: BlockHeader {
            slot: 0,
            proposer_index: 0,
            parent_root: [0u8; 32],
            state_root: [0u8; 32],
            body_root: genesis_body.hash_tree_root(&Sha2Hasher),
        },
        latest_justified: Checkpoint::default(),
        latest_finalized: Checkpoint::default(),
        historical_block_hashes: SszList::new(),
        justified_slots: SszBitlist::new(),
        justification_roots: SszList::new(),
        justification_validators: SszBitlist::new(),
        validators,
    };
    let state_root = state.hash_tree_root(&Sha2Hasher);

    state.latest_block_header = BlockHeader {
        slot: 0,
        proposer_index: 0,
        parent_root: [0u8; 32],
        state_root,
        body_root: genesis_body.hash_tree_root(&Sha2Hasher),
    };

    let genesis = Block {
        slot: 0,
        proposer_index: 0,
        parent_root: [0u8; 32],
        state_root,
        body: genesis_body,
    };

    let genesis_hash = genesis.hash_tree_root(&Sha2Hasher);
    let finalized = Checkpoint {
        root: genesis_hash,
        slot: 0,
    };
    state.latest_justified = finalized.clone();
    state.latest_finalized = finalized.clone();

    let mut store = Store {
        time: 100,
        config: config.clone(),
        head: genesis_hash,
        safe_target: genesis_hash,
        latest_justified: finalized.clone(),
        latest_finalized: finalized.clone(),
        blocks: HashMap::from([(genesis_hash, genesis)]),
        states: HashMap::from([(genesis_hash, state)]),
        latest_known_attestations: HashMap::new(),
        latest_new_attestations: HashMap::new(),
    };

    // Should be able to produce block and attestation
    store.produce_block_with_signature(1, 1).unwrap();

    store.produce_attestation_data(1).unwrap();
}

#[test]
fn test_produce_block_wrong_proposer() {
    let mut store = sample_store();
    let result = store.produce_block_with_signature(5, 3);

    // Correct proposer for slot 5 should be 5 not 3
    assert!(matches!(
        result,
        Err(store::Error::ValidatorIsNotProposer { index: 3, slot: 5 })
    ))
}

#[test]
fn test_produce_block_missing_parent_state() {
    let checkpoint = Checkpoint {
        root: prefixed_bytes("missing"),
        slot: 0,
    };
    let mut store = Store {
        time: 100,
        config: Config { genesis_time: 1000 },
        head: prefixed_bytes("nonexistent"),
        safe_target: prefixed_bytes("nonexistent"),
        latest_justified: checkpoint.clone(),
        latest_finalized: checkpoint.clone(),
        blocks: HashMap::new(),
        states: HashMap::new(),
        latest_known_attestations: HashMap::new(),
        latest_new_attestations: HashMap::new(),
    };

    let result = store.produce_block_with_signature(1, 1);

    // get_proposal_head fails because store.latest_justified is not in store.blocks
    assert!(matches!(result, Err(store::Error::UnknownBlock { .. })))
}
