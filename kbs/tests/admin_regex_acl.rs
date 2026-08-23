// Copyright (c) 2026 by The Trustee Authors
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use actix_web::test::TestRequest;
use kbs::admin::{
    authorization::{
        regex_acl::{RegexAclAuthorizer, RegexAclConfig},
        AuthorizationTrait,
    },
    Claims,
};
use serde_json::json;

#[test]
fn regex_acl_matches_the_request_path_for_an_absolute_uri() {
    let config: RegexAclConfig = serde_json::from_value(json!({
        "acls": [{
            "role": "admin",
            "allowed_endpoints": "^/kbs/v0/resource/.+$"
        }]
    }))
    .expect("valid ACL config");
    let authorizer = RegexAclAuthorizer::try_from(config).expect("valid ACL authorizer");
    let request = TestRequest::post()
        .uri("https://kbs.example.test:8080/kbs/v0/resource/default/key")
        .to_http_request();

    let decision = authorizer
        .authorize(
            Claims {
                role: "admin".to_string(),
            },
            &request,
        )
        .expect("authorization decision");

    assert!(decision.allowed);
}
