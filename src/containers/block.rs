use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
use libssz_types::SszList;

use crate::chain::config::VALIDATOR_REGISTRY_LIMIT;
use crate::containers::attestation::{Attestation, Signature};

pub type AttestationList = SszList<Attestation, VALIDATOR_REGISTRY_LIMIT>;

/// The body of a block, containing payload data.
#[derive(SszEncode, SszDecode, HashTreeRoot, Default)]
pub struct BlockBody {
    /// Plain validator attestations carried in the block body.
    pub attestations: AttestationList,
}

/// The header of a block, containing metadata.
#[derive(SszEncode, SszDecode, HashTreeRoot, Default)]
pub struct BlockHeader {
    /// The slot in which the block was proposed.
    pub slot: u64,

    /// The index of the validator that proposed the block.
    pub proposer_index: u64,

    /// The root of the parent block.
    pub parent_root: [u8; 32],

    /// The root of the state after applying transactions in this block.
    pub state_root: [u8; 32],

    /// The root of the block body.
    pub body_root: [u8; 32],
}

/// A complete block including header and body.
#[derive(SszEncode, SszDecode, HashTreeRoot)]
pub struct Block {
    /// The slot in which the block was proposed.
    pub slot: u64,

    /// The index of the validator that proposed the block.
    pub proposer_index: u64,

    /// The root of the parent block.
    pub parent_root: [u8; 32],

    /// The root of the state after applying transactions in this block.
    pub state_root: [u8; 32],

    /// The block's payload.
    pub body: BlockBody,
}

/// Bundle containing a block and the proposer's attestation
#[derive(SszEncode, SszDecode, HashTreeRoot)]
pub struct BlockWithAttestation {
    /// The proposed block message
    pub block: Block,

    /// The proposer's attestation corresponding to this block.
    pub proposer_attestation: Attestation,
}

/// Envelope carrying a block, an attestation from proposer, and
/// aggregated signatures.
#[derive(SszEncode, SszDecode, HashTreeRoot)]
pub struct SignedBlockWithAttestation {
    /// The block plus an attestation from proposer being signed.
    pub message: BlockWithAttestation,

    /// Aggregated signature payload for the block
    pub signature: SszList<Signature, VALIDATOR_REGISTRY_LIMIT>,
}
