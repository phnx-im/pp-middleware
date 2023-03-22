<!--
SPDX-FileCopyrightText: 2023 Phoenix R&D GmbH <hello@phnx.im>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Privacy Pass middleware

This repository contains a proof-of-concept middleware implementation of a Privacy Pass
protocol server integration. The code is written in Rust and is intended to be
used as a library for other projects. The integration is written as a tower
service (that can be used with axum) and an actix middleware.

## Usage

Examples can be found in the `full_cycle_*` integration tests in `tests/`.
