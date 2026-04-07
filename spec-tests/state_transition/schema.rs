use libssz_types::SszBitlist;
use serde::{Deserialize, Serialize};
use shuri::containers::State;

use crate::common::{
    hex_bytes::HexBytes,
    schema::{
        BlockHeaderSpec, BlockSpec, CheckpointSpec, ConfigSpec, InfoSpec, ValidatorSpec, WrappedVec,
    },
};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StateTransitonTestSpec {
    pub network: String,
    pub pre: PreStateSpec,
    pub blocks: Vec<BlockSpec>,
    pub post: Option<PostStateSpec>,
    pub expect_exception: Option<String>,
    #[serde(rename = "_info")]
    pub info: InfoSpec,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreStateSpec {
    pub config: ConfigSpec,
    pub slot: u64,
    pub latest_block_header: BlockHeaderSpec,
    pub latest_justified: CheckpointSpec,
    pub latest_finalized: CheckpointSpec,
    pub historical_block_hashes: WrappedVec<HexBytes<32>>,
    pub justified_slots: WrappedVec<bool>,
    pub validators: WrappedVec<ValidatorSpec>,
    pub justifications_roots: WrappedVec<HexBytes<32>>,
    pub justifications_validators: WrappedVec<bool>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostStateSpec {
    pub slot: Option<u64>,
    pub latest_justified_slot: Option<u64>,
    pub latest_justified_root: Option<HexBytes<32>>,
    pub latest_finalized_slot: Option<u64>,
    pub latest_finalized_root: Option<HexBytes<32>>,
    pub validator_count: Option<u64>,
    pub config_genesis_time: Option<u64>,
    pub latest_block_header_slot: Option<u64>,
    pub latest_block_header_proposer_index: Option<u64>,
    pub latest_block_header_parent_root: Option<HexBytes<32>>,
    pub latest_block_header_body_root: Option<HexBytes<32>>,
    pub latest_block_header_state_root: Option<HexBytes<32>>,
    pub historical_block_hashes: Option<WrappedVec<HexBytes<32>>>,
    pub justified_slots: Option<WrappedVec<bool>>,
    pub justification_roots: Option<WrappedVec<HexBytes<32>>>,
    pub justification_validators: Option<WrappedVec<bool>>,
}

impl PostStateSpec {
    pub fn validate(&self, state: &State) {
        assert_post_state!(self.slot, state.slot);
        assert_post_state!(self.latest_justified_slot, state.latest_justified.slot);
        assert_post_state!(
            &self.latest_justified_root,
            &HexBytes(state.latest_justified.root)
        );
        assert_post_state!(self.latest_finalized_slot, state.latest_finalized.slot);
        assert_post_state!(
            &self.latest_finalized_root,
            &HexBytes(state.latest_finalized.root)
        );
        assert_post_state!(self.validator_count, state.validators.len() as u64);
        assert_post_state!(self.config_genesis_time, state.config.genesis_time);
        assert_post_state!(
            self.latest_block_header_slot,
            state.latest_block_header.slot
        );
        assert_post_state!(
            self.latest_block_header_proposer_index,
            state.latest_block_header.proposer_index
        );
        assert_post_state!(
            &self.latest_block_header_parent_root,
            &HexBytes(state.latest_block_header.parent_root)
        );
        assert_post_state!(
            &self.latest_block_header_body_root,
            &HexBytes(state.latest_block_header.body_root)
        );
        assert_post_state!(
            &self.latest_block_header_state_root,
            &HexBytes(state.latest_block_header.state_root)
        );
        assert_post_state!(
            &self
                .historical_block_hashes
                .as_ref()
                .map(|h| h.to_sszlist().unwrap()),
            &state.historical_block_hashes
        );
        assert_post_state!(
            &self
                .justified_slots
                .as_ref()
                .map(|js| SszBitlist::try_from(js.data.clone()).unwrap()),
            &state.justified_slots
        );
        assert_post_state!(
            &self
                .justification_roots
                .as_ref()
                .map(|jr| jr.to_sszlist().unwrap()),
            &state.justification_roots
        );
        assert_post_state!(
            &self
                .justification_validators
                .as_ref()
                .map(|jv| SszBitlist::try_from(jv.data.clone()).unwrap()),
            &state.justification_validators
        );
    }
}
