use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

use crate::{
    common::schema::{FixtureFormat, InfoSpec},
    state_transition::schema::StateTransitonTestSpec,
};

#[macro_use]
mod common;
mod state_transition;

fn collect_fixtures(path: &str) -> Result<Vec<PathBuf>, std::io::Error> {
    let mut dirs = vec![PathBuf::from(path)];
    let mut fixtures = Vec::new();
    while let Some(dir) = dirs.pop() {
        let entries = fs::read_dir(dir)?;
        for entry in entries {
            let path = entry?.path();
            if path.is_dir() {
                dirs.push(path);
            } else {
                if let Some(ext) = path.extension()
                    && ext == "json"
                {
                    fixtures.push(path);
                }
            }
        }
    }
    Ok(fixtures)
}

fn main() {
    let fixtures = collect_fixtures("./fixtures").unwrap();
    println!("running {} tests", fixtures.len());
    for entry in fixtures {
        let content = fs::read_to_string(&entry).unwrap();
        print!(
            "test {}::{} ... ",
            entry
                .parent()
                .unwrap()
                .file_name()
                .unwrap()
                .to_str()
                .unwrap(),
            entry.file_stem().unwrap().to_str().unwrap()
        );
        let fixture: HashMap<String, serde_json::Value> = serde_json::from_str(&content).unwrap();
        for (_, value) in fixture.iter() {
            let info: InfoSpec = serde_json::from_value(value["_info"].clone()).unwrap();
            match info.fixture_format {
                FixtureFormat::StateTransitionTest => {
                    let spec: HashMap<String, StateTransitonTestSpec> =
                        serde_json::from_str(&content).unwrap();
                    for test_spec in spec.values() {
                        if std::panic::catch_unwind(|| state_transition::run(test_spec)).is_err() {
                            print!("\x1b[31mFAILED\x1b[0m\n")
                        } else {
                            print!("\x1b[32mok\x1b[0m\n")
                        }
                    }
                }
                FixtureFormat::ForkchoiceTest => println!("unhandled skipping"),
            }
        }
    }
}
