// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod client;
pub mod config;
pub mod extractors;
pub mod reference_value;
pub mod rvps_api;
pub mod server;

use std::sync::Arc;

pub use config::Config;
use key_value_storage::{KeyValueStorage, KeyValueStorageInstance, SetParameters};
pub use reference_value::{ReferenceValue, TrustedDigest};

use extractors::Extractors;

pub use serde_json::Value;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::extractors::ExtractorsConfig;

pub const REFERENCE_VALUE_STORAGE_NAMESPACE: &str = "reference_value";

/// Default version of Message
static MESSAGE_VERSION: &str = "0.1.0";

/// Message is an overall packet that Reference Value Provider Service
/// receives. It will contain payload (content of different provenance,
/// JSON format), provenance type (indicates the type of the payload)
/// and a version number (use to distinguish different version of
/// message, for extendability).
/// * `version`: version of this message.
/// * `payload`: content of the provenance, JSON encoded.
/// * `type`: provenance type of the payload.
#[derive(Serialize, Deserialize, Debug)]
pub struct Message {
    #[serde(default = "default_version")]
    version: String,
    payload: String,
    r#type: String,
}

/// Set the default version for Message
fn default_version() -> String {
    MESSAGE_VERSION.into()
}

/// The core of the RVPS, s.t. componants except communication componants.
pub struct Rvps {
    extractors: Extractors,
    storage: Arc<dyn KeyValueStorage>,
}

impl Rvps {
    pub async fn new_with_storage(
        config: Option<ExtractorsConfig>,
        storage: KeyValueStorageInstance,
    ) -> Result<Self> {
        let extractors = Extractors::new(config)?;
        Ok(Rvps {
            extractors,
            storage,
        })
    }

    /// Instantiate a new RVPS
    pub async fn new(config: Config) -> Result<Self> {
        let extractors = Extractors::new(config.extractors)?;
        let storage = config
            .storage
            .backends
            .to_client_with_namespace(
                config.storage.storage_type,
                REFERENCE_VALUE_STORAGE_NAMESPACE,
            )
            .await?;

        Ok(Rvps {
            extractors,
            storage,
        })
    }

    pub async fn verify_and_extract(&mut self, message: &str) -> Result<()> {
        let message: Message = serde_json::from_str(message).context("parse message")?;

        // Judge the version field
        if message.version != MESSAGE_VERSION {
            bail!(
                "Version unmatched! Need {}, given {}.",
                MESSAGE_VERSION,
                message.version
            );
        }

        let rv = self.extractors.process(message)?;
        for v in rv.iter() {
            let value_bytes = v.to_bytes()?;
            self.storage
                .set(v.name(), &value_bytes, SetParameters { overwrite: true })
                .await?;
        }

        Ok(())
    }

    pub async fn query_reference_value(&self, reference_value_id: &str) -> Result<Option<Value>> {
        let reference_value_vec = self.storage.get(reference_value_id).await?;
        let Some(reference_value_vec) = reference_value_vec else {
            return Ok(None);
        };
        let reference_value: ReferenceValue =
            serde_json::from_slice(&reference_value_vec).context("deserialize reference value")?;

        // Expiration is an authorization boundary, not display metadata. Keep
        // the stored value so a concurrent replacement cannot be deleted by a
        // stale reader, but never return an expired value to an appraisal or
        // resource-policy caller.
        if reference_value.expired() {
            return Ok(None);
        }

        Ok(Some(reference_value.value()))
    }

    pub async fn list_reference_values(&self) -> Result<Vec<String>> {
        Ok(self.storage.list().await?)
    }

    pub async fn delete_reference_value(&self, reference_value_id: &str) -> Result<bool> {
        let deleted = self.storage.delete(reference_value_id).await?;
        Ok(deleted.is_some())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use chrono::{TimeZone, Utc};
    use key_value_storage::{memory::MemoryKeyValueStorage, KeyValueStorage, SetParameters};
    use serde_json::json;

    use super::{ReferenceValue, Rvps};

    #[tokio::test]
    async fn expired_reference_values_are_not_returned() {
        let storage = Arc::new(MemoryKeyValueStorage::default());
        let rvps = Rvps::new_with_storage(None, storage.clone()).await.unwrap();
        let reference = ReferenceValue::new()
            .unwrap()
            .set_name("expired-authorization")
            .set_expiration(Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap())
            .set_value(json!({"state": "authorized"}));

        storage
            .set(
                reference.name(),
                &reference.to_bytes().unwrap(),
                SetParameters { overwrite: true },
            )
            .await
            .unwrap();

        assert_eq!(
            rvps.query_reference_value(reference.name()).await.unwrap(),
            None
        );
        assert!(
            storage.get(reference.name()).await.unwrap().is_some(),
            "an expired read must not race-delete a concurrent replacement"
        );
    }
}
