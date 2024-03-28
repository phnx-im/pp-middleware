// SPDX-FileCopyrightText: 2024 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//! This module contains utility functions for converting between actix/reqwest
//! and http types. This is necessary because actix/reqwest use a different http
//! library to hyper.

use std::str::FromStr;

pub(crate) fn header_value_to_http10(
    header_value: actix_web::http::header::HeaderValue,
) -> http::header::HeaderValue {
    http::header::HeaderValue::from_str(header_value.to_str().unwrap()).unwrap()
}

pub(crate) fn header_name_to_http02(
    header_name: http::header::HeaderName,
) -> actix_web::http::header::HeaderName {
    actix_web::http::header::HeaderName::from_str(header_name.as_str()).unwrap()
}

pub(crate) fn header_value_to_http02(
    header_value: http::header::HeaderValue,
) -> actix_web::http::header::HeaderValue {
    actix_web::http::header::HeaderValue::from_str(header_value.to_str().unwrap()).unwrap()
}

pub(crate) fn uri_to_http10(uri: &actix_web::http::Uri) -> http::Uri {
    http::Uri::from_str(uri.to_string().as_str()).unwrap()
}
