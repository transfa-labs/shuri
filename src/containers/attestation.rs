use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
use libssz_types::{SszBitlist, SszList, SszVector};

use crate::chain::config::VALIDATOR_REGISTRY_LIMIT;
use crate::containers::checkpoint::Checkpoint;

pub type Signature = SszVector<u8, 3116>;
pub type AggregationBits = SszBitlist<VALIDATOR_REGISTRY_LIMIT>;
pub type AggregatedSignatures = SszList<Signature, VALIDATOR_REGISTRY_LIMIT>;

/// Attestation content describing the validator's observed chain view.
#[derive(SszDecode, SszEncode, HashTreeRoot)]
pub struct AttestationData {
    /// The slot for which the attestation is made.
    pub slot: u64,

    /// The checkpoint representing the head block as observed by the validator.
    pub head: Checkpoint,

    /// The checkpoint representing the target block as observed by the validator.
    pub target: Checkpoint,

    /// The checkpoint representing the source block as observed by the validator.
    pub source: Checkpoint,
}

/// Validator specific attestation wrapping shared attestation data.
#[derive(SszDecode, SszEncode, HashTreeRoot)]
pub struct Attestation {
    /// The index of the validator making the attestation.
    pub validator_id: u64,

    /// The attestation data produced by the validator."
    pub data: AttestationData,
}

/// Validator attestation bundled with its signature.
#[derive(SszDecode, SszEncode, HashTreeRoot)]
pub struct SignedAttestation {
    /// The attestation message signed by the validator.
    pub message: Attestation,

    /// Signature aggregation produced by the leanVM (SNARKs in the future).
    pub signature: Signature,
}

/// Aggregated attestation consisting of participation bits and message.
#[derive(SszDecode, SszEncode, HashTreeRoot)]
pub struct AggregatedAttestations {
    /// Bitfield indicating which validators participated in the aggregation.
    pub aggregation_bits: AggregationBits,

    /// Combined attestation data similar to the beacon chain format.
    ///
    /// Multiple validator attestations are aggregated here without the complexity of
    /// committee assignments.
    pub data: AttestationData,
}

/// Aggregated attestation bundled with aggregated signatures.
#[derive(SszDecode, SszEncode, HashTreeRoot)]
pub struct SignedAggregatedAttestations {
    /// Aggregated attestation data.
    pub message: AggregatedAttestations,

    /// Aggregated attestation plus its combined signature.
    ///
    /// Stores a naive list of validator signatures that mirrors the attestation
    /// order.
    pub signature: AggregatedSignatures,
}
