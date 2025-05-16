// SPDX-FileCopyrightText: 2023 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use async_trait::async_trait;
use privacypass::{
    TruncatedTokenKeyId, VoprfServer, common::private::PrivateCipherSuite,
    common::store::PrivateKeyStore,
};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use tokio::sync::Mutex;

use privacypass::{Nonce, NonceStore};

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
pub struct MemoryKeyStore<CS>
where
    CS: PrivateCipherSuite,
{
    keys: Arc<Mutex<HashMap<TruncatedTokenKeyId, VoprfServer<CS>>>>,
}

impl<CS> MemoryKeyStore<CS>
where
    CS: PrivateCipherSuite,
{
    pub fn new() -> Self {
        Self {
            keys: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl<CS: PrivateCipherSuite> PrivateKeyStore for MemoryKeyStore<CS> {
    type CS = CS;

    async fn insert(&self, token_key_id: TruncatedTokenKeyId, server: VoprfServer<CS>) {
        let mut keys = self.keys.lock().await;
        keys.insert(token_key_id, server);
    }

    async fn get(&self, token_key_id: &TruncatedTokenKeyId) -> Option<VoprfServer<CS>> {
        self.keys.lock().await.get(token_key_id).cloned()
    }
}
