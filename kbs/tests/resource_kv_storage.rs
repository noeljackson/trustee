// Copyright (c) 2026 by The Trustee Authors
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use kbs::plugins::resource::{
    kv_storage::KvStorage, ResourceDesc, StorageBackend, RESOURCE_STORAGE_NAMESPACE,
};
use key_value_storage::{KeyValueStorageStructConfig, KeyValueStorageType};

const TEST_DATA: &[u8] = b"testdata";

#[tokio::test]
async fn delete_resource_is_idempotent() {
    let storage = KeyValueStorageStructConfig::default()
        .to_client_with_namespace(KeyValueStorageType::Memory, RESOURCE_STORAGE_NAMESPACE)
        .await
        .expect("create key value storage failed");

    let local_fs = KvStorage::new(storage);
    let resource_desc = ResourceDesc {
        repository_name: "default".into(),
        resource_type: "test".into(),
        resource_tag: "test".into(),
    };

    local_fs
        .write_secret_resource(resource_desc.clone(), TEST_DATA)
        .await
        .expect("write secret resource failed");
    local_fs
        .delete_secret_resource(resource_desc.clone())
        .await
        .expect("first delete failed");
    local_fs
        .delete_secret_resource(resource_desc)
        .await
        .expect("repeated delete failed");
}
