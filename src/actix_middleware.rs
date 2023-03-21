// SPDX-FileCopyrightText: 2023 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use actix_web::{
    dev::{forward_ready, Response, Service, ServiceRequest, ServiceResponse, Transform},
    error::{ErrorInternalServerError, ErrorUnauthorized},
    http::{
        self,
        header::{self, HeaderValue},
        StatusCode,
    },
    web::{self, Bytes, Data},
    Error, HttpRequest, HttpResponse, Responder,
};
use futures_util::future::LocalBoxFuture;
use std::{
    future::{ready, Ready},
    sync::Arc,
};

use privacypass::{
    auth::{
        authenticate::{build_www_authenticate_header, TokenChallenge},
        authorize::parse_authorization_header,
    },
    batched_tokens::{
        server::{serialize_public_key, KeyStore},
        TokenRequest,
    },
    Deserialize, NonceStore,
};

use crate::state::{PrivacyPassProvider, PrivacyPassState};

// There are two steps in middleware processing.
// 1. Middleware initialization, middleware factory gets called with
//    next service in chain as parameter.
// 2. Middleware's call method gets called with normal request.
pub struct PrivacyPassLayer<KS, NS> {
    privacy_pass_state: Arc<PrivacyPassState<KS, NS>>,
}

impl<KS, NS> PrivacyPassLayer<KS, NS> {
    pub fn new(privacy_pass_state: Data<PrivacyPassState<KS, NS>>) -> Self {
        Self {
            privacy_pass_state: privacy_pass_state.into_inner(),
        }
    }
}

// Middleware factory is `Transform` trait
// `S` - type of the next service
// `B` - type of response's body
impl<S, B, KS, NS> Transform<S, ServiceRequest> for PrivacyPassLayer<KS, NS>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
    Response<B>: From<HttpResponse>,
    KS: KeyStore + Sync + Send + 'static,
    NS: NonceStore + Sync + Send + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = PrivacyPassMiddleware<S, KS, NS>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(PrivacyPassMiddleware {
            service,
            privacy_pass_state: self.privacy_pass_state.clone(),
        }))
    }
}

pub struct PrivacyPassMiddleware<S, KS, NS> {
    service: S,
    privacy_pass_state: Arc<PrivacyPassState<KS, NS>>,
}

impl<S, B, KS, NS> Service<ServiceRequest> for PrivacyPassMiddleware<S, KS, NS>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
    Response<B>: From<HttpResponse>,
    KS: KeyStore + Sync + Send + 'static,
    NS: NonceStore + Sync + Send + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let state = self.privacy_pass_state.clone();
        let mut req = req;

        // Extract the authorization header from the request.
        let authorization = req.headers_mut().remove(header::AUTHORIZATION).next();

        // Deserialize the token from the authorization header.
        let token_option =
            authorization.and_then(|header_value| parse_authorization_header(&header_value).ok());

        // If the token is present, then authenticate the token.
        if let Some(token) = token_option {
            let fut = self.service.call(req);
            Box::pin(async move {
                if state.redeem_token(token).await {
                    // If the token is valid, then continue with the request.

                    let res = fut.await?;
                    Ok(res)
                } else {
                    Err(ErrorUnauthorized("Invalid token"))
                }
            })
        } else {
            // If the token is not present, then issue a challenge.
            let public_key = state.public_key();
            let token_key = serialize_public_key(*public_key);
            let build_res =
                build_www_authenticate_header(&challenge(req.request().uri()), &token_key, None);
            if let Ok((header_name, header_value)) = build_res {
                let response = HttpResponse::build(StatusCode::OK)
                    .append_header((header_name, header_value))
                    .finish();

                let sr: ServiceResponse<B> = req.into_response(response);

                Box::pin(async move { Ok(sr) })
            } else {
                Box::pin(async move {
                    Err(ErrorInternalServerError(
                        "Authentication header build error",
                    ))
                })
            }
        }
    }
}

pub(crate) fn challenge(uri: &http::Uri) -> TokenChallenge {
    TokenChallenge::new(
        privacypass::TokenType::Batched,
        &uri.to_string(),
        None,
        &[uri.to_string()],
    )
}

//#[post("/issuer")]
pub async fn issue_token<
    KS: KeyStore + Send + Sync + 'static,
    NS: NonceStore + Send + Sync + 'static,
>(
    body: Bytes,
    req: HttpRequest,
    privacy_pass_state: web::Data<PrivacyPassState<KS, NS>>,
) -> impl Responder {
    // Expect a specific content type
    let content_type = req.headers().get(header::CONTENT_TYPE);
    if content_type != Some(&HeaderValue::from_static("message/token-request")) {
        return HttpResponse::BadRequest().finish();
    }
    // Deserialize the body as a TokenRequest
    if let Ok(token_request) = TokenRequest::tls_deserialize(&mut body.as_ref()) {
        // Make sure that at least one token was requested
        if token_request.nr() == 0 {
            return HttpResponse::BadRequest().finish();
        }
        // Try to issue a token response
        if let Ok(token_response) = privacy_pass_state.issue_token_response(token_request).await {
            HttpResponse::Ok()
                .insert_header((header::CONTENT_TYPE, "message/token-response"))
                .body(token_response)
        } else {
            HttpResponse::BadRequest().finish()
        }
    } else {
        HttpResponse::BadRequest().finish()
    }
}
