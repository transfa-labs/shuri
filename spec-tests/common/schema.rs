use serde::{Deserialize, Serialize};

use libssz_types::SszList;

use crate::common::hex_bytes::HexBytes;

use shuri::containers::{
    Attestation, AttestationData, Block, BlockBody, BlockHeader, Checkpoint, Config, Validator,
};

#[derive(Serialize, Deserialize)]
pub struct WrappedVec<T> {
    pub data: Vec<T>,
}

impl<const N: usize> WrappedVec<HexBytes<N>> {
    pub fn to_sszlist<const M: usize>(
        &self,
    ) -> Result<SszList<[u8; N], M>, libssz_types::TypeError> {
        SszList::try_from(self.data.iter().map(|h| h.0).collect::<Vec<[u8; N]>>())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
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
#[serde(rename_all = "camelCase")]
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
#[serde(rename_all = "camelCase")]
pub struct InfoSpec {
    pub hash: String,
    pub comment: String,
    pub test_id: String,
    pub description: String,
    pub fixture_format: FixtureFormat,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
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
#[serde(rename_all = "camelCase")]
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
    #[serde(rename = "fork_choice_test")]
    ForkchoiceTest,
}
