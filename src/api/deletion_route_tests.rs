// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

//! HTTP contract guards for the deletion routes.

use super::*;
use axum::http::Request;
use tower::ServiceExt;

#[tokio::test]
async fn deletion_routes_require_versions_feature_and_authentication() {
    for enabled in [false, true] {
        let mut config = crate::config::TempestConfig::default();
        config.api.enable_versions_api = enabled;
        config.api.api_key = Some("deletion-test-key-not-a-secret".into());
        let state = crate::server::TftpServer::new(config).state();
        for route in ["/api/v2/delete/preview", "/api/v2/delete/confirm"] {
            let response = api_router(state.clone())
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(route)
                        .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40110))))
                        .header("content-type", "application/json")
                        .body(Body::from("{}"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                if enabled {
                    StatusCode::UNAUTHORIZED
                } else {
                    StatusCode::NOT_FOUND
                }
            );
        }
    }
}

#[tokio::test]
async fn deletion_routes_reject_unknown_fields_and_missing_confirmation() {
    let mut config = crate::config::TempestConfig::default();
    config.api.enable_versions_api = true;
    config.api.allow_insecure_loopback = true;
    let state = crate::server::TftpServer::new(config).state();
    for (route, body) in [
        (
            "preview",
            r#"{"target":{"kind":"file","path":"kernel","force":true}}"#,
        ),
        ("confirm", r#"{"target":{"kind":"file","path":"kernel"}}"#),
        (
            "confirm",
            r#"{"target":{"kind":"file","path":"kernel"},"expected_identity":"bad"}"#,
        ),
    ] {
        let response = api_router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/v2/delete/{route}"))
                    .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40111))))
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(matches!(
            response.status(),
            StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY
        ));
    }
}
