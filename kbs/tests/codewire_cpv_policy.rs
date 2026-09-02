// Copyright (c) 2026 Codewire contributors
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use anyhow::{Context, Result};
use kbs::config::KbsConfig;
use policy_engine::rego::Regorus;
use serde_json::{json, Value};

const POLICY: &str = include_str!("../sample_policies/codewire-cpv-v2.rego");
const ALLOW_RULE: &str = "data.policy.allow";
const ENVIRONMENT_ID: &str = "123e4567-e89b-42d3-a456-426614174000";
const MANIFEST_TAG: &str =
    "sha256-abababababababababababababababababababababababababababababababab";
const OTHER_ENVIRONMENT_ID: &str = "223e4567-e89b-42d3-a456-426614174000";
const OTHER_MANIFEST_TAG: &str =
    "sha256-cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
const INIT_DATA_SHA256: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const NEXT_INIT_DATA_SHA256: &str =
    "3333333333333333333333333333333333333333333333333333333333333333";

#[test]
fn deployment_default_policy_ids_are_loaded_from_config() {
    let config = KbsConfig::try_from(Path::new("test_data/configs/coco-as-grpc-1.toml")).unwrap();

    assert_eq!(
        config.attestation_service.default_policy_ids,
        ["codewire-cpv-v2"]
    );
}

fn approved_ear() -> Value {
    ear(
        ENVIRONMENT_ID,
        MANIFEST_TAG,
        INIT_DATA_SHA256,
        "codewire-cpv-v2",
    )
}

fn ear(environment_id: &str, manifest_tag: &str, init_data_sha256: &str, policy_id: &str) -> Value {
    json!({
        "submods": {
            "cpu0": {
                "ear.status": "affirming",
                "ear.appraisal-policy-id": policy_id,
                "ear.veraison.annotated-evidence": {
                    "snp": {"measurement": "11".repeat(48)},
                    "init_data": init_data_sha256,
                    "init_data_claims": {
                        "codewire_workspace_storage_key_id": environment_id,
                        "codewire_workspace_storage_manifest_tag": manifest_tag,
                    }
                }
            }
        }
    })
}

fn authorization(
    environment_id: &str,
    manifest_tag: &str,
    init_data_sha256: &str,
    state: &str,
) -> Value {
    json!({
        "schema_version": 1,
        "state": state,
        "environment_id": environment_id,
        "storage_manifest_tag": manifest_tag,
        "init_data_sha256": init_data_sha256,
    })
}

fn resource(path: Value) -> Value {
    json!({
        "plugin": "resource",
        "resource-path": path,
        "query": {},
        "codewire_cpv_init_data_authorization": authorization(
            ENVIRONMENT_ID,
            MANIFEST_TAG,
            INIT_DATA_SHA256,
            "authorized",
        ),
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

    let old_policy = ear(
        ENVIRONMENT_ID,
        MANIFEST_TAG,
        INIT_DATA_SHA256,
        "codewire-cpv-v1",
    );
    assert!(!allowed(old_policy, key.clone()).await?);

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
                "ear.appraisal-policy-id": "codewire-cpv-v2",
                "ear.veraison.annotated-evidence": {"sample": {}}
            }
        }
    });
    assert!(!allowed(sample, key).await?);
    Ok(())
}

#[tokio::test]
async fn claim_and_path_substitutions_are_denied() -> Result<()> {
    assert!(
        !allowed(
            approved_ear(),
            resource(json!([
                "default",
                "codewire-workspace-luks",
                OTHER_ENVIRONMENT_ID
            ]))
        )
        .await?
    );
    assert!(
        !allowed(
            approved_ear(),
            resource(json!([
                "default",
                "codewire-storage-manifests",
                OTHER_MANIFEST_TAG
            ]))
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
async fn simultaneous_claim_and_path_substitution_is_denied() -> Result<()> {
    let substituted = ear(
        OTHER_ENVIRONMENT_ID,
        OTHER_MANIFEST_TAG,
        NEXT_INIT_DATA_SHA256,
        "codewire-cpv-v2",
    );
    let request = resource(json!([
        "default",
        "codewire-workspace-luks",
        OTHER_ENVIRONMENT_ID
    ]));

    assert!(!allowed(substituted, request).await?);
    Ok(())
}

#[tokio::test]
async fn live_replacement_denies_an_already_affirming_old_token() -> Result<()> {
    let mut request = resource(json!([
        "default",
        "codewire-workspace-luks",
        ENVIRONMENT_ID
    ]));
    request["codewire_cpv_init_data_authorization"] = authorization(
        ENVIRONMENT_ID,
        MANIFEST_TAG,
        NEXT_INIT_DATA_SHA256,
        "authorized",
    );

    assert!(!allowed(approved_ear(), request).await?);
    Ok(())
}

#[tokio::test]
async fn tombstone_denies_an_already_affirming_token() -> Result<()> {
    let mut request = resource(json!([
        "default",
        "codewire-workspace-luks",
        ENVIRONMENT_ID
    ]));
    request["codewire_cpv_init_data_authorization"] =
        authorization(ENVIRONMENT_ID, MANIFEST_TAG, INIT_DATA_SHA256, "revoked");

    assert!(!allowed(approved_ear(), request).await?);
    Ok(())
}

#[tokio::test]
async fn cross_environment_authorization_substitution_is_denied() -> Result<()> {
    let mut request = resource(json!([
        "default",
        "codewire-workspace-luks",
        ENVIRONMENT_ID
    ]));
    request["codewire_cpv_init_data_authorization"] = authorization(
        OTHER_ENVIRONMENT_ID,
        OTHER_MANIFEST_TAG,
        INIT_DATA_SHA256,
        "authorized",
    );

    assert!(!allowed(approved_ear(), request).await?);
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
