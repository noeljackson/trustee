// Copyright (c) 2026 Codewire contributors
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use serial_test::serial;

extern crate integration_tests;
use integration_tests::common::{
    init_tracing, KbsConfigType, PolicyType, TestHarness, TestParameters,
};

const POLICY_ID: &str = "codewire-cpv-v1";
const ENVIRONMENT_ID: &str = "123e4567-e89b-42d3-a456-426614174000";
const OTHER_ENVIRONMENT_ID: &str = "223e4567-e89b-42d3-a456-426614174000";
const MANIFEST_TAG: &str =
    "sha256-abababababababababababababababababababababababababababababababab";
const KEY_PATH: &str = "default/codewire-workspace-luks/123e4567-e89b-42d3-a456-426614174000";
const MANIFEST_PATH: &str = "default/codewire-storage-manifests/sha256-abababababababababababababababababababababababababababababababab";
const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";
const MANIFEST: &[u8] = b"content-addressed-manifest";

const SAMPLE_AS_POLICY: &str = r#"
package policy
import rego.v1

default executables := 33
default hardware := 97
default configuration := 36
default file_system := 0
default instance_identity := 0
default runtime_opaque := 0
default storage_opaque := 0
default sourced_data := 0

trust_claims := {
    "executables": executables,
    "hardware": hardware,
    "configuration": configuration,
    "file-system": file_system,
    "instance-identity": instance_identity,
    "runtime-opaque": runtime_opaque,
    "storage-opaque": storage_opaque,
    "sourced-data": sourced_data,
}

bound_init_data if {
    input.sample
    input.init_data
    is_object(input.init_data_claims)
}

executables := 3 if {
    bound_init_data
    input.sample.launch_digest in query_reference_value("launch_digest")
}

hardware := 2 if {
    bound_init_data
    input.sample.svn in query_reference_value("svn")
    input.sample.platform_version.major == query_reference_value("major_version")
    input.sample.platform_version.minor >= query_reference_value("minimum_minor_version")
}

configuration := 2 if {
    bound_init_data
    input.sample.debug == false
}
"#;

fn parameters(default_policy_id: &str) -> TestParameters {
    let parameters: TestParameters = KbsConfigType::EarTokenRemoteRvps.into();
    parameters.with_default_policy_ids([default_policy_id])
}

fn init_data(environment_id: &str, manifest_tag: &str) -> String {
    format!(
        r#"version = "0.1.0"
algorithm = "sha256"

[data]
codewire_workspace_storage_key_id = "{environment_id}"
codewire_workspace_storage_manifest_tag = "{manifest_tag}"
"#
    )
}

fn sample_resource_policy() -> &'static str {
    Box::leak(
        include_str!("../../kbs/sample_policies/codewire-cpv-v1.rego")
            .replace("evidence.snp != null", "evidence.sample != null")
            .into_boxed_str(),
    )
}

async fn install_policies(harness: &TestHarness, policy_id: &str) -> Result<()> {
    harness
        .set_policy(PolicyType::Custom(sample_resource_policy()))
        .await?;
    harness
        .set_attestation_policy(SAMPLE_AS_POLICY.to_string(), format!("{policy_id}_cpu"))
        .await?;
    Ok(())
}

async fn install_reference_values(harness: &TestHarness, svn: &str) -> Result<()> {
    for (name, value) in [
        ("svn", json!([svn])),
        ("launch_digest", json!(["abcde"])),
        ("major_version", json!(1)),
        ("minimum_minor_version", json!(1)),
    ] {
        harness.set_reference_value(name.to_string(), value).await?;
    }
    Ok(())
}

fn appraisal(payload: &Value) -> &Value {
    &payload["submods"]["cpu0"]
}

async fn assert_resource_denied(
    harness: &TestHarness,
    path: &str,
    init_data: Option<String>,
) -> Result<()> {
    if harness
        .get_secret(path.to_string(), init_data)
        .await
        .is_ok()
    {
        bail!("resource {path} was released when denial was required");
    }
    Ok(())
}

#[serial(integration_ports)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn configured_policy_releases_only_the_exact_measured_tuple() -> Result<()> {
    init_tracing();
    let harness = TestHarness::new(parameters(POLICY_ID)).await?;

    let result = async {
        install_policies(&harness, POLICY_ID).await?;
        install_reference_values(&harness, "1").await?;
        harness.set_secret(KEY_PATH.into(), SECRET.into()).await?;
        harness
            .set_secret(MANIFEST_PATH.into(), MANIFEST.into())
            .await?;

        let measured_init_data = init_data(ENVIRONMENT_ID, MANIFEST_TAG);
        assert_eq!(
            harness
                .get_secret(KEY_PATH.into(), Some(measured_init_data.clone()))
                .await?,
            SECRET
        );
        assert_eq!(
            harness
                .get_secret(MANIFEST_PATH.into(), Some(measured_init_data.clone()))
                .await?,
            MANIFEST
        );

        let token = harness
            .get_attestation_token_payload(Some(measured_init_data.clone()))
            .await?;
        assert_eq!(appraisal(&token)["ear.status"], "affirming");
        assert_eq!(appraisal(&token)["ear.appraisal-policy-id"], POLICY_ID);

        assert_resource_denied(
            &harness,
            &KEY_PATH.replace(ENVIRONMENT_ID, OTHER_ENVIRONMENT_ID),
            Some(measured_init_data.clone()),
        )
        .await?;
        assert_resource_denied(
            &harness,
            KEY_PATH,
            Some(init_data(OTHER_ENVIRONMENT_ID, MANIFEST_TAG)),
        )
        .await?;
        assert_resource_denied(&harness, KEY_PATH, None).await?;
        assert_resource_denied(
            &harness,
            KEY_PATH,
            Some("this is not valid init-data TOML".into()),
        )
        .await?;

        Ok(())
    }
    .await;

    harness.cleanup().await?;
    result
}

#[serial(integration_ports)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stale_tcb_produces_a_nonaffirming_appraisal_and_denial() -> Result<()> {
    init_tracing();
    let harness = TestHarness::new(parameters(POLICY_ID)).await?;

    let result = async {
        install_policies(&harness, POLICY_ID).await?;
        install_reference_values(&harness, "stale").await?;
        harness.set_secret(KEY_PATH.into(), SECRET.into()).await?;

        let measured_init_data = init_data(ENVIRONMENT_ID, MANIFEST_TAG);
        let token = harness
            .get_attestation_token_payload(Some(measured_init_data.clone()))
            .await?;
        assert_ne!(appraisal(&token)["ear.status"], "affirming");
        assert_resource_denied(&harness, KEY_PATH, Some(measured_init_data)).await
    }
    .await;

    harness.cleanup().await?;
    result
}

#[serial(integration_ports)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn affirming_generic_default_policy_cannot_release_cpv_resources() -> Result<()> {
    init_tracing();
    let harness = TestHarness::new(parameters("default")).await?;

    let result = async {
        install_policies(&harness, "default").await?;
        install_reference_values(&harness, "1").await?;
        harness.set_secret(KEY_PATH.into(), SECRET.into()).await?;

        let measured_init_data = init_data(ENVIRONMENT_ID, MANIFEST_TAG);
        let token = harness
            .get_attestation_token_payload(Some(measured_init_data.clone()))
            .await?;
        assert_eq!(appraisal(&token)["ear.status"], "affirming");
        assert_eq!(appraisal(&token)["ear.appraisal-policy-id"], "default");
        assert_resource_denied(&harness, KEY_PATH, Some(measured_init_data)).await
    }
    .await;

    harness.cleanup().await?;
    result.context("generic default policy must not authorize CPV resources")
}
