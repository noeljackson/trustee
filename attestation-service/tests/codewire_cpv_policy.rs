// Copyright (c) 2026 Codewire contributors
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashMap, sync::Arc};

use anyhow::{Context, Result};
use policy_engine::rego::{Regorus, RegorusExtension};
use serde_json::{json, Value};

const POLICY: &str = include_str!("../policies/codewire-cpv-v1_cpu.rego");
const TRUST_CLAIMS_RULE: &str = "data.policy.trust_claims";

fn reference_values() -> HashMap<String, Value> {
    HashMap::from([
        ("snp_launch_measurement".into(), json!(["11".repeat(48)])),
        ("snp_bootloader".into(), json!([3])),
        ("snp_microcode".into(), json!([4])),
        ("snp_snp_svn".into(), json!([5])),
        ("snp_tee_svn".into(), json!([6])),
        ("snp_smt_enabled".into(), json!(true)),
        ("snp_tsme_enabled".into(), json!(false)),
        ("snp_guest_abi_major".into(), json!(1)),
        ("snp_guest_abi_minor".into(), json!(51)),
        ("snp_single_socket".into(), json!(true)),
        ("snp_smt_allowed".into(), json!(true)),
    ])
}

fn approved_snp_claims() -> Value {
    json!({
        "init_data": "22".repeat(32),
        "init_data_claims": {
            "codewire_workspace_storage_key_id": "123e4567-e89b-42d3-a456-426614174000",
            "codewire_workspace_storage_manifest_tag": format!("sha256-{}", "ab".repeat(32)),
        },
        "snp": {
            "measurement": "11".repeat(48),
            "reported_tcb_bootloader": 3,
            "reported_tcb_microcode": 4,
            "reported_tcb_snp": 5,
            "reported_tcb_tee": 6,
            "policy_debug_allowed": false,
            "policy_migrate_ma": false,
            "platform_smt_enabled": true,
            "platform_tsme_enabled": false,
            "policy_abi_major": 1,
            "policy_abi_minor": 51,
            "policy_single_socket": true,
            "policy_smt_allowed": true,
        }
    })
}

async fn evaluate(input: Value, reference_values: HashMap<String, Value>) -> Result<Value> {
    let reference_values = Arc::new(reference_values);
    let extension = RegorusExtension {
        name: "query_reference_value".to_string(),
        id: 1,
        extension: Box::new(move |params| {
            let id = params
                .first()
                .context("reference-value ID is required")?
                .as_string()
                .context("reference-value ID must be a string")?;
            let value = reference_values
                .get(id.as_ref())
                .cloned()
                .unwrap_or(Value::Null);
            serde_json::from_value(value).context("convert reference value")
        }),
    };

    let result = Regorus::default()
        .evaluate(
            None,
            input.to_string(),
            POLICY.to_string(),
            vec![TRUST_CLAIMS_RULE.to_string()],
            vec![extension],
        )
        .await?;

    result.eval_rules_result[TRUST_CLAIMS_RULE]
        .clone()
        .context("policy omitted trust claims")
}

fn assert_affirming(claims: &Value) {
    assert_eq!(claims["executables"], 3);
    assert_eq!(claims["hardware"], 2);
    assert_eq!(claims["configuration"], 2);
}

fn assert_contraindicated(claims: &Value) {
    assert!(claims["executables"] != 3 || claims["hardware"] != 2 || claims["configuration"] != 2);
}

#[tokio::test]
async fn exact_bound_snp_evidence_is_affirming() -> Result<()> {
    let claims = evaluate(approved_snp_claims(), reference_values()).await?;
    assert_affirming(&claims);
    Ok(())
}

#[tokio::test]
async fn missing_init_data_is_contraindicated() -> Result<()> {
    let mut input = approved_snp_claims();
    input.as_object_mut().unwrap().remove("init_data");

    let claims = evaluate(input, reference_values()).await?;
    assert_contraindicated(&claims);
    Ok(())
}

#[tokio::test]
async fn malformed_init_data_hash_is_contraindicated() -> Result<()> {
    let mut input = approved_snp_claims();
    input["init_data"] = json!("not-a-host-data-digest");

    let claims = evaluate(input, reference_values()).await?;
    assert_contraindicated(&claims);
    Ok(())
}

#[tokio::test]
async fn stale_tcb_reference_is_contraindicated() -> Result<()> {
    let mut references = reference_values();
    references.insert("snp_microcode".into(), json!([99]));

    let claims = evaluate(approved_snp_claims(), references).await?;
    assert_contraindicated(&claims);
    Ok(())
}

#[tokio::test]
async fn missing_tcb_reference_is_contraindicated() -> Result<()> {
    let mut references = reference_values();
    references.remove("snp_launch_measurement");

    let claims = evaluate(approved_snp_claims(), references).await?;
    assert_contraindicated(&claims);
    Ok(())
}

#[tokio::test]
async fn unsupported_attester_is_contraindicated() -> Result<()> {
    let input = json!({
        "init_data": "22".repeat(32),
        "init_data_claims": {},
        "sample": {"debug": false},
    });

    let claims = evaluate(input, reference_values()).await?;
    assert_contraindicated(&claims);
    Ok(())
}
