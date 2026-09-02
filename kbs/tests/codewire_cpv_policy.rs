// Copyright (c) 2026 Codewire contributors
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use anyhow::{Context, Result};
use kbs::config::KbsConfig;
use policy_engine::rego::Regorus;
use serde_json::{json, Value};

const POLICY: &str = include_str!("../sample_policies/codewire-cpv-v1.rego");
const ALLOW_RULE: &str = "data.policy.allow";
const ENVIRONMENT_ID: &str = "123e4567-e89b-42d3-a456-426614174000";
const MANIFEST_TAG: &str =
    "sha256-abababababababababababababababababababababababababababababababab";

#[test]
fn deployment_default_policy_ids_are_loaded_from_config() {
    let config = KbsConfig::try_from(Path::new("test_data/configs/coco-as-grpc-1.toml")).unwrap();

    assert_eq!(
        config.attestation_service.default_policy_ids,
        ["codewire-cpv-v1"]
    );
}

fn approved_ear() -> Value {
    json!({
        "submods": {
            "cpu0": {
                "ear.status": "affirming",
                "ear.appraisal-policy-id": "codewire-cpv-v1",
                "ear.veraison.annotated-evidence": {
                    "snp": {"measurement": "11".repeat(48)},
                    "init_data_claims": {
                        "codewire_workspace_storage_key_id": ENVIRONMENT_ID,
                        "codewire_workspace_storage_manifest_tag": MANIFEST_TAG,
                    }
                }
            }
        }
    })
}

fn resource(path: Value) -> Value {
    json!({
        "plugin": "resource",
        "resource-path": path,
        "query": {},
    })
}

async fn allowed(input: Value, data: Value) -> Result<bool> {
    let result = Regorus::default()
        .evaluate(
            Some(data.to_string()),
            input.to_string(),
            POLICY.to_string(),
            vec![ALLOW_RULE.to_string()],
            vec![],
        )
        .await?;

    result.eval_rules_result[ALLOW_RULE]
        .as_ref()
        .and_then(Value::as_bool)
        .context("policy allow result must be a boolean")
}

#[tokio::test]
async fn exact_measured_key_and_manifest_paths_are_allowed() -> Result<()> {
    assert!(
        allowed(
            approved_ear(),
            resource(json!([
                "default",
                "codewire-workspace-luks",
                ENVIRONMENT_ID
            ]))
        )
        .await?
    );
    assert!(
        allowed(
            approved_ear(),
            resource(json!([
                "default",
                "codewire-storage-manifests",
                MANIFEST_TAG
            ]))
        )
        .await?
    );
    Ok(())
}

#[tokio::test]
async fn broad_or_wrong_appraisals_are_denied() -> Result<()> {
    let key = resource(json!([
        "default",
        "codewire-workspace-luks",
        ENVIRONMENT_ID
    ]));

    let mut wrong_policy = approved_ear();
    wrong_policy["submods"]["cpu0"]["ear.appraisal-policy-id"] = json!("default");
    assert!(!allowed(wrong_policy, key.clone()).await?);

    let mut nonaffirming = approved_ear();
    nonaffirming["submods"]["cpu0"]["ear.status"] = json!("contraindicated");
    assert!(!allowed(nonaffirming, key.clone()).await?);

    let mut missing_status = approved_ear();
    missing_status["submods"]["cpu0"]
        .as_object_mut()
        .unwrap()
        .remove("ear.status");
    assert!(!allowed(missing_status, key.clone()).await?);

    let mut missing_policy = approved_ear();
    missing_policy["submods"]["cpu0"]
        .as_object_mut()
        .unwrap()
        .remove("ear.appraisal-policy-id");
    assert!(!allowed(missing_policy, key.clone()).await?);

    let mut extra_unapproved_device = approved_ear();
    extra_unapproved_device["submods"]["gpu0"] = json!({
        "ear.status": "affirming",
        "ear.appraisal-policy-id": "default",
    });
    assert!(!allowed(extra_unapproved_device, key.clone()).await?);

    let sample = json!({
        "submods": {
            "cpu0": {
                "ear.status": "affirming",
                "ear.appraisal-policy-id": "codewire-cpv-v1",
                "ear.veraison.annotated-evidence": {"sample": {}}
            }
        }
    });
    assert!(!allowed(sample, key).await?);
    Ok(())
}

#[tokio::test]
async fn claim_and_path_substitutions_are_denied() -> Result<()> {
    let other_id = "223e4567-e89b-42d3-a456-426614174000";
    let other_tag = format!("sha256-{}", "cd".repeat(32));

    assert!(
        !allowed(
            approved_ear(),
            resource(json!(["default", "codewire-workspace-luks", other_id]))
        )
        .await?
    );
    assert!(
        !allowed(
            approved_ear(),
            resource(json!(["default", "codewire-storage-manifests", other_tag]))
        )
        .await?
    );

    let mut malformed_claims = approved_ear();
    malformed_claims["submods"]["cpu0"]["ear.veraison.annotated-evidence"]["init_data_claims"]
        ["codewire_workspace_storage_key_id"] = json!("not-a-uuid");
    assert!(
        !allowed(
            malformed_claims,
            resource(json!([
                "default",
                "codewire-workspace-luks",
                ENVIRONMENT_ID
            ]))
        )
        .await?
    );
    Ok(())
}

#[tokio::test]
async fn alternate_namespaces_plugins_and_queries_are_denied() -> Result<()> {
    let mut alias = resource(json!(["default", "storage-keys", ENVIRONMENT_ID]));
    assert!(!allowed(approved_ear(), alias.clone()).await?);

    alias["plugin"] = json!("sample");
    assert!(!allowed(approved_ear(), alias).await?);

    let mut queried = resource(json!([
        "default",
        "codewire-workspace-luks",
        ENVIRONMENT_ID
    ]));
    queried["query"] = json!({"version": "old"});
    assert!(!allowed(approved_ear(), queried).await?);
    Ok(())
}
