// SPDX-FileCopyrightText: 2023 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::{
    routing::{get, post},
    Extension, Router,
};
use privacypass::{
    auth::{authenticate::parse_www_authenticate_header, authorize::build_authorization_header},
    batched_tokens_ristretto255::{server::*, TokenResponse},
    Serialize,
};
use privacypass_middleware::{
    axum_middleware::*,
    memory_stores::{MemoryKeyStore, MemoryNonceStore},
    state::PrivacyPassState,
};
use reqwest::{
    header::{HeaderValue, CONTENT_TYPE},
    StatusCode,
};
use std::sync::Arc;
use tower_http::trace::TraceLayer;

/// Sample server using axum. The server exposes two endpoints:
///  - GET /origin - a sample endpoint that requires authentication with
///    Privacy Pass
///  - POST /issuer - an endpoint that issues Privacy Pass tokens
async fn run_server() {
    let ks = MemoryKeyStore::default();
    let ns = MemoryNonceStore::default();
    let privacy_pass_state = Arc::new(PrivacyPassState::new(ks, ns).await);
    let privacy_pass_layer = PrivacyPassLayer::new(privacy_pass_state.clone());

    let app = Router::new()
        .route("/origin", get(origin))
        .route_layer(privacy_pass_layer.clone())
        .route(
            "/issuer",
            post(issue_token::<MemoryKeyStore, MemoryNonceStore>),
        )
        .route_layer(Extension(privacy_pass_state.clone()))
        .layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}

/// Origin endpoint
async fn origin() -> &'static str {
    "Origin"
}

/// Full cycle of receiving a challenge, issuing a token and authenticating
/// a request.
#[tokio::test]
async fn full_cycle_axum() {
    // Number of tokens to request
    let nr = 1;

    // Spawn the server
    tokio::spawn(run_server());

    // Instantiate the HTTP client
    let http_client = reqwest::Client::new();

    // Fetch the origin to receive a challenge
    let res = http_client
        .get("http://localhost:3000/origin")
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);

    // Extract token challenge from header
    let header_name = reqwest::header::WWW_AUTHENTICATE;
    let header_value = res.headers().get(header_name).unwrap().clone();

    assert_eq!(res.bytes().await.unwrap().len(), 0);

    let challenges = parse_www_authenticate_header(&header_value).unwrap();
    assert_eq!(challenges.len(), 1);
    let challenge = &challenges[0];

    let token_challenge = challenge.token_challenge();

    // Instantiate the Privacy Pass client
    let public_key = deserialize_public_key(challenge.token_key()).unwrap();

    let client = privacypass::batched_tokens_ristretto255::client::Client::new(public_key);

    assert_eq!(challenge.max_age(), None);

    // Create a token request
    let (token_request, token_states) = client.issue_token_request(token_challenge, nr).unwrap();

    // Request a token
    let res = http_client
        .post("http://localhost:3000/issuer")
        .header(
            CONTENT_TYPE,
            HeaderValue::from_static("message/token-request"),
        )
        .body(token_request.tls_serialize_detached().unwrap())
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers().get(reqwest::header::CONTENT_TYPE).unwrap(),
        HeaderValue::from_static("message/token-response")
    );

    // Process the token response
    let token_response_bytes = res.bytes().await.unwrap();
    let token_response = TokenResponse::try_from_bytes(&token_response_bytes).unwrap();

    // Generate the tokens
    let tokens = client.issue_tokens(&token_response, &token_states).unwrap();
    assert_eq!(tokens.len(), nr as usize);

    // Redeem a token
    let (header_name, header_value) = build_authorization_header(&tokens[0]).unwrap();

    let res = http_client
        .get("http://localhost:3000/origin")
        .header(header_name.clone(), header_value.clone())
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.text().await.unwrap(), "Origin");

    // Test double spending
    let res = http_client
        .get("http://localhost:3000/origin")
        .header(header_name, header_value)
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}
