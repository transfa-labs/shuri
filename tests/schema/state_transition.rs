use libssz_types::{SszBitlist, SszList};
use serde::{Deserialize, Serialize};
use similar_asserts::assert_eq;

use crate::helpers::hex_bytes::HexBytes;
use shuri::containers::{
    Attestation, AttestationData, Block, BlockBody, BlockHeader, Checkpoint, Config, State,
    Validator,
};

#[derive(Serialize, Deserialize)]
pub struct StateTransitonTestSpec {
    pub network: String,
    pub pre: PreStateSpec,
    pub blocks: Vec<BlockSpec>,
    pub post: PostStateSpec,
    pub _info: InfoSpec,
}

impl StateTransitonTestSpec {
    fn run(&self) {
        let mut state = State {
            config: Config {
                genesis_time: self.pre.config.genesis_time,
            },
            latest_block_header: (&self.pre.latest_block_header).into(),
            slot: self.pre.slot,
            latest_justified: (&self.pre.latest_justified).into(),
            latest_finalized: (&self.pre.latest_finalized).into(),
            historical_block_hashes: self.pre.historical_block_hashes.to_sszlist().unwrap(),
            justified_slots: self.pre.justified_slots.data.clone().try_into().unwrap(),
            validators: self
                .pre
                .validators
                .data
                .iter()
                .map(Into::into)
                .collect::<Vec<Validator>>()
                .try_into()
                .unwrap(),
            justification_roots: self.pre.justification_roots.to_sszlist().unwrap(),
            justification_validators: self
                .pre
                .justification_validators
                .data
                .clone()
                .try_into()
                .unwrap(),
        };
        let blocks = self.blocks.iter().map(Into::into).collect::<Vec<Block>>();
        for block in blocks {
            state.state_transition(&block);
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct WrappedVec<T> {
    pub data: Vec<T>,
}

impl<const N: usize> WrappedVec<HexBytes<N>> {
    fn to_sszlist<const M: usize>(&self) -> Result<SszList<[u8; N], M>, libssz_types::TypeError> {
        SszList::try_from(
            self.data
                .iter()
                .map(|h| h.0.clone())
                .collect::<Vec<[u8; N]>>(),
        )
    }
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

impl From<ConfigSpec> for Config {
    fn from(value: ConfigSpec) -> Self {
        Self {
            genesis_time: value.genesis_time,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct BlockHeaderSpec {
    pub slot: u64,
    pub proposer_index: u64,
    pub state_root: HexBytes<32>,
    pub parent_root: HexBytes<32>,
    pub body_root: HexBytes<32>,
}

impl From<&BlockHeaderSpec> for BlockHeader {
    fn from(value: &BlockHeaderSpec) -> Self {
        Self {
            slot: value.slot,
            proposer_index: value.proposer_index,
            parent_root: *value.parent_root,
            state_root: *value.state_root,
            body_root: *value.body_root,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct CheckpointSpec {
    pub slot: u64,
    pub root: HexBytes<32>,
}

impl From<&CheckpointSpec> for Checkpoint {
    fn from(value: &CheckpointSpec) -> Self {
        Self {
            slot: value.slot,
            root: *value.root,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct ValidatorSpec {
    pub index: u64,
    pub pubkey: HexBytes<52>,
}

impl From<&ValidatorSpec> for Validator {
    fn from(value: &ValidatorSpec) -> Self {
        Self {
            index: value.index,
            pubkey: *value.pubkey,
        }
    }
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

impl From<&BlockSpec> for Block {
    fn from(value: &BlockSpec) -> Self {
        Self {
            slot: value.slot,
            proposer_index: value.proposer_index,
            parent_root: *value.parent_root,
            state_root: *value.state_root,
            body: BlockBody {
                attestations: value
                    .body
                    .attestations
                    .data
                    .iter()
                    .map(Into::into)
                    .collect::<Vec<Attestation>>()
                    .try_into()
                    .unwrap(),
            },
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct BlockBodySpec {
    pub attestations: WrappedVec<AttestationSpec>,
}

#[derive(Serialize, Deserialize)]
pub struct AttestationSpec {
    pub validator_id: u64,
    pub data: AttestationDataSpec,
}

impl From<&AttestationSpec> for Attestation {
    fn from(value: &AttestationSpec) -> Self {
        Self {
            validator_id: value.validator_id,
            data: (&value.data).into(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct AttestationDataSpec {
    pub slot: u64,
    pub head: CheckpointSpec,
    pub target: CheckpointSpec,
    pub source: CheckpointSpec,
}

impl From<&AttestationDataSpec> for AttestationData {
    fn from(value: &AttestationDataSpec) -> Self {
        Self {
            slot: value.slot,
            head: (&value.head).into(),
            source: (&value.source).into(),
            target: (&value.target).into(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub enum FixtureFormat {
    #[serde(rename = "state_transition_test")]
    StateTransitionTest,
}
