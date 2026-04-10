mod attestation;
pub mod block;
mod checkpoint;
mod config;
mod slot;
pub mod state;
mod validator;

pub use attestation::{
    AggregatedAttestations, AggregatedSignatures, AggregationBits, Attestation, AttestationData,
    Signature, SignedAggregatedAttestations, SignedAttestation,
};
pub use block::{Block, BlockBody, BlockHeader, BlockWithAttestation, SignedBlockWithAttestation};
pub use checkpoint::Checkpoint;
pub use config::Config;
pub use slot::Slot;
pub use state::State;
pub use validator::{Pubkey, Validator};
