use std::{collections::HashMap, fs, panic::AssertUnwindSafe, path::PathBuf, process};

use crate::common::schema::{FixtureFormat, InfoSpec};

#[macro_use]
mod common;
mod state_transition;

struct Fixture {
    suite: String,
    case: String,
    content: String,
}

enum Outcome {
    Failure { msg: String },
    Success,
    Ignored,
}

struct Test {
    suite: String,
    case: String,
    description: String,
    outcome: Outcome,
}

fn collect_fixtures(path: &str) -> Result<Vec<Fixture>, std::io::Error> {
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
                    let suite = path
                        .parent()
                        .and_then(|f| f.file_name())
                        .and_then(|f| f.to_str())
                        .expect("path should have a parent dir");
                    let case = path
                        .file_stem()
                        .and_then(|f| f.to_str())
                        .expect("path should have a file name");

                    let content = fs::read_to_string(&path)?;
                    fixtures.push(Fixture {
                        suite: suite.into(),
                        case: case.into(),
                        content: content.into(),
                    });
                }
            }
        }
    }
    Ok(fixtures)
}

fn run_single(runner: impl Fn()) -> Outcome {
    match std::panic::catch_unwind(AssertUnwindSafe(runner)) {
        Ok(_) => Outcome::Success,
        Err(e) => {
            let msg = e
                .downcast_ref::<String>()
                .map(|s| s.as_str())
                .or(e.downcast_ref::<&str>().map(|s| *s))
                .unwrap_or("test panicked");
            Outcome::Failure { msg: msg.into() }
        }
    }
}

fn print_outcome(outcome: &Outcome) {
    let output = match outcome {
        Outcome::Success => "\x1b[32mok\x1b[0m",
        Outcome::Failure { .. } => "\x1b[31mFAILED\x1b[0m",
        Outcome::Ignored => "\x1b[33mignored\x1b[0m",
    };
    println!("{}", output);
}

fn handle_fixture(fixture: Fixture) -> Test {
    print!("test {}::{} ... ", fixture.suite, fixture.case);

    let parsed: HashMap<String, serde_json::Value> =
        serde_json::from_str(&fixture.content).unwrap();

    let value = parsed.values().nth(0).unwrap();
    let info: InfoSpec = serde_json::from_value(value["_info"].clone()).unwrap();

    let outcome = match info.fixture_format {
        FixtureFormat::StateTransitionTest => {
            run_test_case(&fixture.content, state_transition::run)
        }
        FixtureFormat::ForkchoiceTest => Outcome::Ignored,
    };

    print_outcome(&outcome);

    Test {
        suite: fixture.suite,
        case: fixture.case,
        description: info.description,
        outcome,
    }
}

fn run_test_case<'de, T: serde::Deserialize<'de>>(
    content: &'de str,
    runner: impl Fn(&T),
) -> Outcome {
    let spec: HashMap<String, T> = serde_json::from_str(content).unwrap();

    let test_case = spec
        .values()
        .nth(0)
        .expect("spec should only have one test case");

    run_single(|| runner(test_case))
}

fn main() {
    let fixtures = collect_fixtures("./fixtures").unwrap();

    println!("running {} tests", fixtures.len());

    let mut failed_tests = Vec::new();
    let mut passed = 0;
    let mut failed = 0;
    let mut ignored = 0;

    for fixture in fixtures {
        let test = handle_fixture(fixture);
        match test.outcome {
            Outcome::Success => {
                passed += 1;
            }
            Outcome::Failure { .. } => {
                failed += 1;
                failed_tests.push(test);
            }
            Outcome::Ignored => {
                ignored += 1;
            }
        }
    }

    if failed > 0 {
        println!("\nfailures: ");

        for test in &failed_tests {
            if let Outcome::Failure { msg } = &test.outcome {
                println!("\n----- {}::{} -----", test.suite, test.case);
                println!("Description");
                println!("===========");
                println!("{}", test.description);
                println!();
                println!("Test Output");
                println!("===========");
                println!("{}", msg);
            }
        }
    }

    println!();
    println!(
        "summary: {} passed, {} failed and {} ignored",
        passed, failed, ignored
    );

    if failed > 0 {
        process::exit(1);
    }
}
