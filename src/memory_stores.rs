// SPDX-FileCopyrightText: 2023 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use async_trait::async_trait;
use privacypass::TokenKeyId;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use tokio::sync::Mutex;

use privacypass::{
    batched_tokens::{server::*, *},
    Nonce, NonceStore,
};

#[derive(Default, Clone)]
pub struct MemoryNonceStore {
    nonces: Arc<Mutex<HashSet<Nonce>>>,
}

#[async_trait]
impl NonceStore for MemoryNonceStore {
    async fn exists(&self, nonce: &Nonce) -> bool {
        let nonces = self.nonces.lock().await;
        nonces.contains(nonce)
    }

    async fn insert(&self, nonce: Nonce) {
        let mut nonces = self.nonces.lock().await;
        nonces.insert(nonce);
    }
}

#[derive(Default, Clone)]
pub struct MemoryKeyStore {
    keys: Arc<Mutex<HashMap<TokenKeyId, VoprfServer<Ristretto255>>>>,
}

#[async_trait]
impl BatchedKeyStore for MemoryKeyStore {
    async fn insert(&self, token_key_id: TokenKeyId, server: VoprfServer<Ristretto255>) {
        let mut keys = self.keys.lock().await;
        keys.insert(token_key_id, server);
    }

    async fn get(&self, token_key_id: &TokenKeyId) -> Option<VoprfServer<Ristretto255>> {
        self.keys.lock().await.get(token_key_id).cloned()
    }
}
