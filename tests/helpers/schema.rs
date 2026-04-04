use serde::{Deserialize, Serialize};

use crate::helpers::hex_bytes::HexBytes;
use shuri::containers::state::State;

#[derive(Serialize, Deserialize)]
pub struct StateTransitonTestSpec {
    pub network: String,
    pub pre: PreStateSpec,
    pub block: Vec<BlockSpec>,
    pub post: PostStateSpec,
    pub _info: InfoSpec,
}

impl StateTransitonTestSpec {
    fn run(&self) {
        let pre_state = State {
            config: Config
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct WrappedVec<T> {
    pub data: Vec<T>,
}

#[derive(Serialize, Deserialize)]
pub struct PreStateSpec {
    pub config: ConfigSpec,
    pub slot: u64,
    pub latest_block_header: BlockHeaderSpec,
    pub latest_justified: CheckpointSpec,
    pub latest_finalized: CheckpointSpec,
    pub historical_block_hashes: WrappedVec<HexBytes<32>>,
    pub justified_slots: WrappedVec<bool>,
    pub validators: WrappedVec<ValidatorSpec>,
    pub justification_roots: WrappedVec<HexBytes<32>>,
    pub justification_validators: WrappedVec<bool>,
}

#[derive(Serialize, Deserialize)]
pub struct ConfigSpec {
    pub genesis_time: u64,
}

#[derive(Serialize, Deserialize)]
pub struct BlockHeaderSpec {
    pub slot: u64,
    pub proposer_index: u64,
    pub state_root: HexBytes<32>,
    pub parent_root: HexBytes<32>,
    pub body_root: HexBytes<32>,
}

#[derive(Serialize, Deserialize)]
pub struct CheckpointSpec {
    pub slot: u64,
    pub root: HexBytes<32>,
}

#[derive(Serialize, Deserialize)]
pub struct ValidatorSpec {
    pub index: u64,
    pub pubkey: HexBytes<52>,
}

#[derive(Serialize, Deserialize)]
pub struct PostStateSpec {
    pub slot: u64,
    pub latest_justified_slot: u64,
    pub latest_justified_root: HexBytes<32>,
    pub latest_finalized_slot: u64,
    pub latest_finalized_root: HexBytes<32>,
    pub validator_count: u64,
    pub config_genesis_time: u64,
    pub latest_block_header_slot: u64,
    pub latest_block_header_proposer_index: u64,
    pub latest_block_header_parent_root: HexBytes<32>,
    pub latest_block_header_body_root: HexBytes<32>,
    pub latest_block_header_state_root: HexBytes<32>,
    pub historical_block_hashes: WrappedVec<HexBytes<32>>,
    pub justified_slots: WrappedVec<bool>,
    pub justification_roots: WrappedVec<HexBytes<32>>,
    pub justification_validators: WrappedVec<bool>,
}

#[derive(Serialize, Deserialize)]
pub struct InfoSpec {
    pub hash: String,
    pub comment: String,
    pub test_id: String,
    pub description: String,
    pub fixture_format: String,
}

#[derive(Serialize, Deserialize)]
pub struct BlockSpec {
    pub slot: u64,
    pub proposer_index: u64,
    pub parent_root: HexBytes<32>,
    pub state_root: HexBytes<32>,
    pub body: BlockBodySpec,
}

#[derive(Serialize, Deserialize)]
pub struct BlockBodySpec {
    pub attestations: Vec<AttestationSpec>,
}

#[derive(Serialize, Deserialize)]
pub struct AttestationSpec {
    pub validator_id: u64,
    pub data: AttestationDataSpec,
}

#[derive(Serialize, Deserialize)]
pub struct AttestationDataSpec {
    pub slot: u64,
    pub head: CheckpointSpec,
    pub target: CheckpointSpec,
    pub source: CheckpointSpec,
}

#[derive(Serialize, Deserialize)]
pub enum FixtureFormat {
    #[serde(rename = "state_transition_test")]
    StateTransitionTest,
}
