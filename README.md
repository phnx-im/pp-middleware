<!--
SPDX-FileCopyrightText: 2023 Phoenix R&D GmbH <hello@phnx.im>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Privacy Pass Proof-of-Concept

This repository contains a proof-of-concept implementation of a Privacy Pass
protocol server integration. The code is written in Rust and is intended to be
used as a library for other projects. The integration is written as a tower
service, which can be used as a middelware for HTTP requests in the axum
framework.

## Usage

An example can be found in the `full_cycle` integration test in `src/lib.rs`.
