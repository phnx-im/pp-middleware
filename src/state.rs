use async_trait::async_trait;
use privacypass::{batched_tokens::server::Server, TokenKeyId};
use std::collections::{HashMap, HashSet};
use tokio::sync::Mutex;

use privacypass::{
    batched_tokens::{server::*, *},
    Nonce, NonceStore, Serialize,
};

pub(crate) struct PrivacyPassState {
    key_store: MemoryKeyStore,
    nonce_store: MemoryNonceStore,
    server: Mutex<Server>,
    public_key: PublicKey,
}

impl PrivacyPassState {
    pub(crate) async fn new() -> Self {
        let mut server = Server::new();
        let mut key_store = MemoryKeyStore::default();
        let public_key = server.create_keypair(&mut key_store).await.unwrap();

        Self {
            key_store,
            nonce_store: MemoryNonceStore::default(),
            server: Mutex::new(server),
            public_key,
        }
    }

    pub(crate) fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub(crate) async fn issue_token_response(
        &self,
        token_request: TokenRequest,
    ) -> Result<Vec<u8>, IssueTokenResponseError> {
        let mut server = self.server.lock().await;
        let token_response = server
            .issue_token_response(&self.key_store, token_request)
            .await
            .unwrap();
        token_response
            .tls_serialize_detached()
            .map_err(|_| IssueTokenResponseError::InvalidTokenRequest)
    }

    pub(crate) async fn redeem_token(&self, token: BatchedToken) -> bool {
        let server = self.server.lock().await;
        server
            .redeem_token(&self.key_store, &self.nonce_store, token.clone())
            .await
            .is_ok()
    }
}

#[derive(Default)]
pub struct MemoryNonceStore {
    nonces: Mutex<HashSet<Nonce>>,
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

#[derive(Default)]
pub struct MemoryKeyStore {
    keys: Mutex<HashMap<TokenKeyId, VoprfServer<Ristretto255>>>,
}

#[async_trait]
impl KeyStore for MemoryKeyStore {
    async fn insert(&self, token_key_id: TokenKeyId, server: VoprfServer<Ristretto255>) {
        let mut keys = self.keys.lock().await;
        keys.insert(token_key_id, server);
    }

    async fn get(&self, token_key_id: &TokenKeyId) -> Option<VoprfServer<Ristretto255>> {
        self.keys.lock().await.get(token_key_id).cloned()
    }
}
