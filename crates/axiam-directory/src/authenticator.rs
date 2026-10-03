//! The [`DirectoryAuthenticator`] the composition root injects into the login
//! path: the stored configuration, the decrypted bind secret and the
//! [`DirectoryClient`], put together per tenant.
//!
//! # Fail closed, per tenant
//!
//! * No configuration, or a disabled one: [`DirectoryAuthError::NotConfigured`].
//! * The bind secret cannot be decrypted — above all because the optional
//!   `directory_encryption_key` is not configured (D-15) — is
//!   [`DirectoryAuthError::Unavailable`]: the feature is off, not insecure.
//! * A stored row that would not pass `config::validate` today (a plaintext
//!   URL, an unusable anchor) is [`DirectoryAuthError::Misconfigured`] and never
//!   reaches a socket. Validation runs at save time; this is the bind path
//!   refusing to trust that it did.
//!
//! The configuration is read on every authentication, so a change made through
//! the management API applies to the next sign-in. Only the TLS client
//! configuration is cached, keyed by the row's generation (`id`, `updated_at`),
//! because building a root store from the public bundle on every sign-in would
//! be waste.
//!
//! # Cross-tenant confusion
//!
//! Every lookup is keyed by the tenant the login path resolved — the tenant the
//! caller is signing in to — and the pool is partitioned by the same id, so one
//! tenant's sign-in can never be answered by, or reuse a connection bound for,
//! another tenant's directory.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axiam_core::error::AxiamError;
use axiam_core::models::directory::{
    DirectoryAuthError, DirectoryAuthenticator, DirectoryConfig, DirectoryIdentity,
};
use axiam_core::repository::DirectoryConfigRepository;
use rustls::ClientConfig;
use uuid::Uuid;

use crate::client::{DirectoryClient, DirectoryTarget, transport_is_encrypted};
use crate::tls::client_config;

/// The production [`DirectoryAuthenticator`]: a configuration repository and
/// the shared [`DirectoryClient`].
pub struct RepositoryDirectoryAuthenticator<R> {
    repo: R,
    client: Arc<DirectoryClient>,
    tls_cache: Mutex<HashMap<Uuid, (String, Arc<ClientConfig>)>>,
}

impl<R: DirectoryConfigRepository> RepositoryDirectoryAuthenticator<R> {
    /// An authenticator over `repo`, with a client at the default bounds.
    pub fn new(repo: R) -> Self {
        Self::with_client(repo, Arc::new(DirectoryClient::default()))
    }

    /// An authenticator over `repo` sharing `client` (tests shrink its bounds).
    pub fn with_client(repo: R, client: Arc<DirectoryClient>) -> Self {
        Self {
            repo,
            client,
            tls_cache: Mutex::new(HashMap::new()),
        }
    }

    async fn run(
        &self,
        tenant_id: Uuid,
        login_name: &str,
        password: &str,
    ) -> Result<DirectoryIdentity, DirectoryAuthError> {
        // Before any lookup, as the client also does: the answer to an empty
        // password does not depend on the tenant's configuration.
        if password.is_empty() {
            return Err(DirectoryAuthError::InvalidCredentials);
        }
        let config = match self.repo.get_by_tenant(tenant_id).await {
            Ok(Some(config)) if config.enabled => config,
            Ok(_) => return Err(DirectoryAuthError::NotConfigured),
            Err(error) => {
                tracing::warn!(
                    target: "axiam::directory",
                    tenant_id = %tenant_id,
                    error = %error,
                    "directory configuration could not be read"
                );
                return Err(DirectoryAuthError::Unavailable);
            }
        };
        let secret = match self.repo.decrypt_bind_secret(tenant_id).await {
            Ok(secret) => secret,
            Err(AxiamError::NotFound { .. }) => return Err(DirectoryAuthError::NotConfigured),
            Err(error) => {
                // `ServiceUnavailable` names the missing key; the message
                // carries no secret material.
                tracing::warn!(
                    target: "axiam::directory",
                    tenant_id = %tenant_id,
                    error = %error,
                    "directory bind secret could not be decrypted"
                );
                return Err(DirectoryAuthError::Unavailable);
            }
        };
        let target = self.target(&config)?;
        self.client
            .authenticate(&target, &secret, login_name, password)
            .await
    }

    fn target(&self, config: &DirectoryConfig) -> Result<DirectoryTarget, DirectoryAuthError> {
        if !transport_is_encrypted(&config.url, config.start_tls) {
            tracing::warn!(
                target: "axiam::directory",
                tenant_id = %config.tenant_id,
                "the stored directory URL is not encrypted; refusing to connect"
            );
            return Err(DirectoryAuthError::Misconfigured);
        }
        let generation = format!(
            "{}:{}",
            config.id,
            config.updated_at.timestamp_nanos_opt().unwrap_or_default()
        );
        let tls = self.tls_for(config, &generation)?;
        Ok(DirectoryTarget {
            tenant_id: config.tenant_id,
            generation,
            url: config.url.clone(),
            start_tls: config.start_tls,
            bind_dn: config.bind_dn.clone(),
            base_dn: config.base_dn.clone(),
            user_filter: config.user_filter.clone(),
            attributes: config.user_attribute_map.clone(),
            tls,
        })
    }

    fn tls_for(
        &self,
        config: &DirectoryConfig,
        generation: &str,
    ) -> Result<Arc<ClientConfig>, DirectoryAuthError> {
        let mut cache = self
            .tls_cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((cached_generation, tls)) = cache.get(&config.tenant_id)
            && cached_generation == generation
        {
            return Ok(Arc::clone(tls));
        }
        let tls = client_config(&config.trust_anchors_pem).map_err(|error| {
            tracing::warn!(
                target: "axiam::directory",
                tenant_id = %config.tenant_id,
                error = %error,
                "the stored directory trust anchors are unusable"
            );
            DirectoryAuthError::Misconfigured
        })?;
        cache.insert(config.tenant_id, (generation.to_string(), Arc::clone(&tls)));
        Ok(tls)
    }
}

impl<R: DirectoryConfigRepository> DirectoryAuthenticator for RepositoryDirectoryAuthenticator<R> {
    fn authenticate<'a>(
        &'a self,
        tenant_id: Uuid,
        login_name: &'a str,
        password: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<DirectoryIdentity, DirectoryAuthError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(self.run(tenant_id, login_name, password))
    }
}
