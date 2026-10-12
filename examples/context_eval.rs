//! Reproducible, provider-free context component evaluation.
//! Run: cargo run --locked --release --example context_eval

use anyhow::{ensure, Result};
use audit_harness::{
    context::history::{project_result, serialized_bytes, ResultArchive},
    provider::{
        conversation::{Conversation, TurnDecoder},
        wire::WireApi,
    },
};
use serde_json::json;
use std::{hint::black_box, time::Instant};

fn tool_turn(id: usize) -> Result<audit_harness::provider::conversation::Turn> {
    let mut decoder = TurnDecoder::new(WireApi::ChatCompletions);
    decoder.handle_data(
        &json!({"choices":[{"delta":{"reasoning_content":"working", "tool_calls":[{"index":0,"id":format!("call-{id}"),"type":"function","function":{"name":"bash","arguments":"{}"}}]},"finish_reason":"tool_calls"}]}).to_string(),
        &mut (),
    )?;
    decoder.handle_data("[DONE]", &mut ())?;
    decoder.finish()
}

fn conversation(turns: usize, result_bytes: usize) -> Result<Conversation> {
    let mut conversation = Conversation::with_tools(
        WireApi::ChatCompletions,
        "fixture",
        "system",
        "source",
        32_768,
        vec![],
    );
    conversation.set_reasoning_effort("high");
    let result = json!({"stdout":"x".repeat(result_bytes),"exit_code":0}).to_string();
    for id in 0..turns {
        conversation.append(&tool_turn(id)?, std::slice::from_ref(&result))?;
    }
    Ok(conversation)
}

fn median(mut values: Vec<u128>) -> u128 {
    values.sort_unstable();
    values[values.len() / 2]
}

fn main() -> Result<()> {
    let mut default = conversation(16, 16_000)?;
    let mut archive = ResultArchive::default();
    let default_result = default.reduce_context(2 * 1024 * 1024, 2, &mut archive)?;
    ensure!(
        default_result.pruned_results == 0,
        "default-sized fixture pruned"
    );

    let mut pressure = conversation(160, 70_000)?;
    let mut archive = ResultArchive::default();
    let pressure_result = pressure.reduce_context(2 * 1024 * 1024, 2, &mut archive)?;
    let pressure_stats = archive.stats();
    ensure!(
        pressure_result.pruned_results > 120,
        "pressure fixture did not prune"
    );
    ensure!(
        pressure_stats.distinct_files == 1,
        "identical outputs were not shared"
    );
    ensure!(
        serialized_bytes(&pressure.body)? == pressure_result.after_bytes,
        "size accounting drift"
    );

    let mut protected = conversation(4, 70_000)?;
    let mut archive = ResultArchive::default();
    let protected_result = protected.reduce_context(128 * 1024, 2, &mut archive)?;
    ensure!(
        protected_result.after_bytes > 128 * 1024,
        "protected-context fixture unexpectedly fit"
    );

    let output = json!({"stdout": "雪\"\\\n".repeat(150_000), "exit_code": 7}).to_string();
    let mut projection_times = Vec::new();
    for _ in 0..7 {
        let started = Instant::now();
        for _ in 0..128 {
            let projected = project_result(&output, 1024, Some("/tmp/observed.json"))?;
            ensure!(projected.len() <= 1024, "projection exceeded cap");
            black_box(projected);
        }
        projection_times.push(started.elapsed().as_micros());
    }

    let repeated = "observed output".repeat(32_768);
    let mut reuse_times = Vec::new();
    for _ in 0..7 {
        let mut archive = ResultArchive::default();
        let path = archive.save(&repeated)?.expect("first output fits archive");
        let started = Instant::now();
        for _ in 0..128 {
            ensure!(
                archive.save(&repeated)?.as_deref() == Some(path.as_str()),
                "reuse mismatch"
            );
        }
        reuse_times.push(started.elapsed().as_micros());
        ensure!(
            archive.stats().distinct_files == 1,
            "reuse spent file quota"
        );
    }
    println!(
        "{}",
        json!({
            "schema_version":1,
            "fixed_reasoning_effort":"high",
            "default":default_result,
            "pressure":pressure_result,
            "pressure_archive":pressure_stats,
            "protected":protected_result,
            "projection_128_median_us":median(projection_times),
            "archive_reuse_128_median_us":median(reuse_times),
        })
    );
    Ok(())
}
