use std::{collections::HashMap, fs, path::Path};

use crate::helpers::schema::{FixtureFormat, StateTransitonTestSpec};

pub mod hex_bytes;
pub mod schema;

pub fn test_spec(dir: impl AsRef<Path>, name: &str, format: &FixtureFormat) {
    let spec_dir = dir.as_ref().join(name);
    for entry in spec_dir.read_dir().unwrap() {
        let entry = entry.unwrap();
        let content = fs::read_to_string(entry.path()).unwrap();
        match format {
            FixtureFormat::StateTransitionTest => {
                let spec: HashMap<String, StateTransitonTestSpec> =
                    serde_json::from_str(&content).unwrap();
            }
        }
    }
}
