use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
use libssz_merkle::{HashTreeRoot, Sha2Hasher};
use libssz_types::SszList;

use crate::chain::config::VALIDATOR_REGISTRY_LIMIT;
use crate::containers::State;
use crate::containers::attestation::{Attestation, Signature};
use crate::crypto::xmss;

pub type AttestationList = SszList<Attestation, VALIDATOR_REGISTRY_LIMIT>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("number of signatures does not match number of attestations")]
    SignatureCountMismatch,

    #[error("validator index out of range")]
    IndexOutOfRange,

    #[error("attestation signature verification failed")]
    SignatureVerificationFailure(#[from] xmss::Error),
}

/// The body of a block, containing payload data.
#[derive(SszEncode, SszDecode, HashTreeRoot, Default, Debug)]
pub struct BlockBody {
    /// Plain validator attestations carried in the block body.
    pub attestations: AttestationList,
}

/// The header of a block, containing metadata.
#[derive(SszEncode, SszDecode, HashTreeRoot, Default, Debug, Clone)]
pub struct BlockHeader {
    /// The slot in which the block was proposed.
    pub slot: u64,

    /// The index  the validator that proposed the block.
    pub proposer_index: u64,

    /// The root of the parent block.
    pub parent_root: [u8; 32],

    /// The root of the state after applying transactions in this block.
    pub state_root: [u8; 32],

    /// The root of the block body.
    pub body_root: [u8; 32],
}

/// A complete block including header and body.
#[derive(SszEncode, SszDecode, HashTreeRoot, Debug)]
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
#[derive(SszEncode, SszDecode, HashTreeRoot, Debug)]
pub struct BlockWithAttestation {
    /// The proposed block message
    pub block: Block,

    /// The proposer's attestation corresponding to this block.
    pub proposer_attestation: Attestation,
}

/// Envelope carrying a block, an attestation from proposer, and
/// aggregated signatures.
#[derive(SszEncode, SszDecode, HashTreeRoot, Debug)]
pub struct SignedBlockWithAttestation {
    /// The block plus an attestation from proposer being signed.
    pub message: BlockWithAttestation,

    /// Aggregated signature payload for the block
    pub signature: SszList<Signature, VALIDATOR_REGISTRY_LIMIT>,
}

impl SignedBlockWithAttestation {
    /// Verify all XMSS signatures in this signed block
    pub fn verify_signatures(&self, parent_state: &State) -> Result<(), Error> {
        let all_attestations: Vec<_> = self
            .message
            .block
            .body
            .attestations
            .iter()
            .chain([&self.message.proposer_attestation])
            .collect();
        if self.signature.len() != all_attestations.len() {
            return Err(Error::SignatureCountMismatch);
        }

        for (attestation, signature) in all_attestations.iter().zip(self.signature.iter()) {
            let validator_id = attestation.validator_id as usize;
            if validator_id >= parent_state.validators.len() {
                return Err(Error::IndexOutOfRange);
            }
            let validator = &parent_state.validators[validator_id];
            xmss::verify_signature(
                &validator.pubkey,
                attestation.data.slot,
                &attestation.hash_tree_root(&Sha2Hasher),
                signature,
            )?;
        }
        Ok(())
    }
}
