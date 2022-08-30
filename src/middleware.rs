use axum::{
    body::{Body, Bytes},
    http::{self, HeaderValue, Request},
    response::{IntoResponse, Response},
    Extension,
};
use futures::future::BoxFuture;
use hyper::{HeaderMap, StatusCode, Uri};
use privacypass::{
    auth::{
        authenticate::{build_www_authenticate_header, TokenChallenge},
        authorize::parse_authorization_header,
    },
    batched_tokens::{server::serialize_public_key, TokenRequest},
    Deserialize,
};
use std::{
    sync::Arc,
    task::{Context, Poll},
};
use tower::{Layer, Service};

use crate::state::PrivacyPassState;

#[derive(Clone)]
pub(crate) struct PrivacyPassLayer {
    privacy_pass_state: Arc<PrivacyPassState>,
}

impl PrivacyPassLayer {
    pub fn new(privacy_pass_state: Arc<PrivacyPassState>) -> Self {
        Self { privacy_pass_state }
    }
}

impl<S> Layer<S> for PrivacyPassLayer {
    type Service = PrivacyPassMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        PrivacyPassMiddleware {
            inner,
            state: self.privacy_pass_state.clone(),
        }
    }
}

#[derive(Clone)]
pub(crate) struct PrivacyPassMiddleware<S> {
    inner: S,
    state: Arc<PrivacyPassState>,
}

impl<S> Service<Request<Body>> for PrivacyPassMiddleware<S>
where
    S: Service<Request<Body>, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        let not_ready_inner = self.inner.clone();
        let mut ready_inner = std::mem::replace(&mut self.inner, not_ready_inner);
        let state = self.state.clone();

        // Extract the authorization header from the request.
        let authorization = req.headers_mut().remove(http::header::AUTHORIZATION);

        // Deserialize the token from the authorization header.
        let token_option =
            authorization.and_then(|header_value| parse_authorization_header(&header_value).ok());

        // If the token is present, then authenticate the token.
        if let Some(token) = token_option {
            Box::pin(async move {
                if state.redeem_token(token).await {
                    // If the token is valid, then continue with the request.
                    let future = ready_inner.call(req);
                    future.await
                } else {
                    Ok(StatusCode::UNAUTHORIZED.into_response())
                }
            })
        } else {
            // If the token is not present, then issue a challenge.
            let public_key = state.public_key();
            let token_key = serialize_public_key(*public_key);
            let build_res = build_www_authenticate_header(&challenge(req.uri()), &token_key, None);
            if let Ok((header_name, header_value)) = build_res {
                let mut response = ().into_response();
                response.headers_mut().insert(header_name, header_value);

                Box::pin(async move { Ok(response) })
            } else {
                Box::pin(async move { Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response()) })
            }
        }
    }
}

pub(crate) fn challenge(uri: &Uri) -> TokenChallenge {
    TokenChallenge::new(
        privacypass::TokenType::Batched,
        &uri.to_string(),
        None,
        &[uri.to_string()],
    )
}

pub(crate) async fn issue_token(
    body: Bytes,
    headers: HeaderMap,
    Extension(privacy_pass_state): Extension<Arc<PrivacyPassState>>,
) -> Response {
    // Expect a specific content type
    let content_type = headers.get(http::header::CONTENT_TYPE);
    if content_type != Some(&HeaderValue::from_static("message/token-request")) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    // Deserialize the body as a TokenRequest
    if let Ok(token_request) = TokenRequest::tls_deserialize(&mut body.as_ref()) {
        // Make sure that at least one token was requested
        if token_request.nr() == 0 {
            return StatusCode::BAD_REQUEST.into_response();
        }
        // Try to issue a token response
        if let Ok(token_response) = privacy_pass_state.issue_token_response(token_request).await {
            let mut response = token_response.into_response();
            // Set the header type
            response.headers_mut().insert(
                http::header::CONTENT_TYPE,
                HeaderValue::from_static("message/token-response"),
            );
            response
        } else {
            StatusCode::BAD_REQUEST.into_response()
        }
    } else {
        StatusCode::BAD_REQUEST.into_response()
    }
}
