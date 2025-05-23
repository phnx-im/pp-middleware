// SPDX-FileCopyrightText: 2022 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use async_trait::async_trait;
use privacypass::{
    amortized_tokens::{AmortizedBatchTokenRequest, AmortizedToken, server::Server},
    common::{errors::IssueTokenResponseError, private::PublicKey, store::PrivateKeyStore},
};

use tokio::sync::Mutex;

use privacypass::{NonceStore, Serialize};

/// This is a trait that provides a set of methods for issuing and redeeming
/// privacy-pass tokens. The trait has two generic parameters: KS and NS. KS is
/// a type parameter that is used to specify the type of keystore used to store
/// key pairs, while NS is a type parameter that is used to specify the type
/// of nonce store used to store nonces.
#[async_trait]
pub trait PrivacyPassProvider<KS, NS>
where
    KS: PrivateKeyStore + Send + Sync + 'static,
    NS: NonceStore + Send + Sync + 'static,
{
    /// This method returns a reference to the public key of the server.
    fn public_key(&self) -> &PublicKey<KS::CS>;

    /// This method returns a reference to the server.
    fn server(&self) -> &Mutex<Server<KS::CS>>;

    /// This method returns a reference to the keystore.
    fn key_store(&self) -> &KS;

    /// This method returns a reference to the nonce store.
    fn nonce_store(&self) -> &NS;

    /// This method is used to issue a token response to a token request.
    async fn issue_token_response(
        &self,
        token_request: AmortizedBatchTokenRequest<KS::CS>,
    ) -> Result<Vec<u8>, IssueTokenResponseError> {
        let server = self.server().lock();
        let ks = self.key_store();
        let token_response = server
            .await
            .issue_token_response(ks, token_request)
            .await
            .map_err(|_| IssueTokenResponseError::KeyIdNotFound)?;
        token_response
            .tls_serialize_detached()
            .map_err(|_| IssueTokenResponseError::InvalidTokenRequest)
    }

    /// This method is used to redeem a token.
    async fn redeem_token(&self, token: AmortizedToken<KS::CS>) -> bool {
        let server = self.server().lock().await;
        let ks = self.key_store();
        let ns = self.nonce_store();
        let res = server.redeem_token(ks, ns, token.clone()).await;
        res.is_ok()
    }
}

/// This is a struct that implements the PrivacyPassProvider trait. It is used
/// to store the state of the server.
pub struct PrivacyPassState<KS, NS>
where
    KS: PrivateKeyStore + Send + Sync + 'static,
{
    key_store: KS,
    nonce_store: NS,
    server: Mutex<Server<KS::CS>>,
    public_key: PublicKey<KS::CS>,
}

#[async_trait]
impl<KS, NS> PrivacyPassProvider<KS, NS> for PrivacyPassState<KS, NS>
where
    KS: PrivateKeyStore + Send + Sync + 'static,
    NS: NonceStore + 'static,
{
    fn public_key(&self) -> &PublicKey<KS::CS> {
        &self.public_key
    }

    fn server(&self) -> &Mutex<Server<KS::CS>> {
        &self.server
    }

    fn key_store(&self) -> &KS {
        &self.key_store
    }

    fn nonce_store(&self) -> &NS {
        &self.nonce_store
    }
}

impl<KS, NS> PrivacyPassState<KS, NS>
where
    KS: PrivateKeyStore + Send + Sync + 'static,
    NS: NonceStore + Default + 'static,
{
    /// This method is used to create a new instance of the PrivacyPassState
    /// struct. It takes a key store and a nonce store as parameters.
    ///
    /// It creates a key pair and stores it in the key store. The public key is
    /// exposed and can be used to extract the private key from the store.
    ///
    /// While the key store can handle multiple keys, this state object is
    /// specific to one key, and a new state object should be created for each
    /// key.
    pub async fn new(ks: KS, ns: NS) -> Self {
        let server = Server::new();
        let public_key = server.create_keypair(&ks).await.unwrap();

        Self {
            key_store: ks,
            nonce_store: ns,
            server: Mutex::new(server),
            public_key,
        }
    }
}
