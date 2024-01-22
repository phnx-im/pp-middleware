// SPDX-FileCopyrightText: 2023 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use actix_web::{
    http::{self, header::HeaderValue, StatusCode},
    rt, web, App, HttpResponse, HttpServer, Responder,
};
use privacypass::{
    auth::{authenticate::parse_www_authenticate_header, authorize::build_authorization_header},
    batched_tokens::{server::*, TokenResponse},
    Serialize,
};
use privacypass_middleware::{
    actix_middleware::*,
    memory_stores::{MemoryKeyStore, MemoryNonceStore},
    state::PrivacyPassState,
    utils::{header_name_to_http02, header_value_to_http02, header_value_to_http10},
};
use std::{sync::Arc, thread};

/// Sample server using actix. The server exposes two endpoints:
///  - GET /origin - a sample endpoint that requires authentication with
///    Privacy Pass
///  - POST /issuer - an endpoint that issues Privacy Pass tokens
async fn run_server() -> std::io::Result<()> {
    let ks = MemoryKeyStore::default();
    let ns = MemoryNonceStore::default();
    let privacy_pass_state = PrivacyPassState::new(ks, ns).await;
    let privacy_pass_state_data = web::Data::new(privacy_pass_state);
    let privacy_pass_layer = Arc::new(PrivacyPassLayer::new(privacy_pass_state_data.clone()));

    HttpServer::new(move || {
        App::new()
            .service(
                web::resource("/origin")
                    .route(web::get().to(origin))
                    .wrap(privacy_pass_layer.clone()),
            )
            .service(
                web::resource("/issuer")
                    .route(web::post().to(issue_token::<MemoryKeyStore, MemoryNonceStore>)),
            )
            .app_data(privacy_pass_state_data.clone())
    })
    .bind(("127.0.0.1", 3001))
    .unwrap()
    .run()
    .await
}

async fn origin() -> impl Responder {
    HttpResponse::Ok().body("Origin")
}

/// Full cycle of receiving a challenge, issuing a token and authenticating
/// a request.
#[tokio::test]
async fn full_cycle_actix() {
    // Number of tokens to request
    let nr = 1;

    // Spawn the server
    thread::spawn(move || {
        let server_future = run_server();
        rt::System::new().block_on(server_future)
    });

    // Instantiate the HTTP client
    let http_client = reqwest::Client::new();

    // Fetch the origin to receive a challenge
    let res = http_client
        .get("http://localhost:3001/origin")
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);

    // Extract token challenge from header
    let header_name = http::header::WWW_AUTHENTICATE;
    let header_value = header_value_to_http10(res.headers().get(header_name).unwrap().clone());

    assert_eq!(res.bytes().await.unwrap().len(), 0);

    let challenges = parse_www_authenticate_header(&header_value).unwrap();
    assert_eq!(challenges.len(), 1);
    let challenge = &challenges[0];

    let token_challenge = challenge.token_challenge();

    // Instantiate the Privacy Pass client
    let public_key = deserialize_public_key(challenge.token_key()).unwrap();

    let client = privacypass::batched_tokens::client::Client::new(public_key);

    assert_eq!(challenge.max_age(), None);

    // Create a token request
    let (token_request, token_states) = client.issue_token_request(token_challenge, nr).unwrap();

    // Request a token
    let res = http_client
        .post("http://localhost:3001/issuer")
        .header(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("message/token-request"),
        )
        .body(token_request.tls_serialize_detached().unwrap())
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers().get(http::header::CONTENT_TYPE).unwrap(),
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

    let header_name = header_name_to_http02(header_name);
    let header_value = header_value_to_http02(header_value);

    let res = http_client
        .get("http://localhost:3001/origin")
        .header(header_name.clone(), header_value.clone())
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.text().await.unwrap(), "Origin");

    // Test double spending
    let res = http_client
        .get("http://localhost:3001/origin")
        .header(header_name, header_value)
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}
