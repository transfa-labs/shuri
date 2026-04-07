use shuri::containers::{Block, Config, State, Validator};

use crate::state_transition::schema::StateTransitonTestSpec;

pub fn run(spec: &StateTransitonTestSpec) {
    let mut state = State {
        config: Config {
            genesis_time: spec.pre.config.genesis_time,
        },
        latest_block_header: (&spec.pre.latest_block_header).into(),
        slot: spec.pre.slot,
        latest_justified: (&spec.pre.latest_justified).into(),
        latest_finalized: (&spec.pre.latest_finalized).into(),
        historical_block_hashes: spec.pre.historical_block_hashes.to_sszlist().unwrap(),
        justified_slots: spec.pre.justified_slots.data.clone().try_into().unwrap(),
        validators: spec
            .pre
            .validators
            .data
            .iter()
            .map(Into::into)
            .collect::<Vec<Validator>>()
            .try_into()
            .unwrap(),
        justification_roots: spec.pre.justifications_roots.to_sszlist().unwrap(),
        justification_validators: spec
            .pre
            .justifications_validators
            .data
            .clone()
            .try_into()
            .unwrap(),
    };
    let blocks = spec.blocks.iter().map(Into::into).collect::<Vec<Block>>();
    let result = blocks
        .iter()
        .map(|block| state.state_transition(block))
        .collect::<Result<Vec<_>, _>>();
    if spec.expect_exception.is_some() {
        assert!(result.is_err());
        return;
    }

    result.unwrap();

    if let Some(post) = &spec.post {
        post.validate(&state);
    }
}
