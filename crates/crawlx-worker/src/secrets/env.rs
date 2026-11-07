//! `env://VAR`: the process environment.

use super::{strip_scheme, SecretError};
use async_trait::async_trait;
use crawlx_core::secret::{CredentialRef, SecretOr, SecretResolver};
use crawlx_core::CoreError;

/// Resolves `env://VAR` references from the process environment.
#[derive(Clone, Copy, Debug, Default)]
pub struct EnvSecretResolver;

impl EnvSecretResolver {
    /// Value of the variable named by `reference`.
    ///
    /// # Errors
    /// [`SecretError::UnsupportedScheme`] for another scheme, [`SecretError::EnvUnset`]
    /// when the variable is unset or empty.
    pub fn lookup(&self, reference: &CredentialRef) -> Result<SecretOr<String>, SecretError> {
        let var = strip_scheme(reference, "env")?;
        match std::env::var(var) {
            Ok(v) if !v.is_empty() => Ok(SecretOr::secret(v)),
            _ => Err(SecretError::EnvUnset {
                reference: reference.0.clone(),
            }),
        }
    }
}

#[async_trait]
impl SecretResolver for EnvSecretResolver {
    async fn resolve(&self, reference: &CredentialRef) -> Result<SecretOr<String>, CoreError> {
        Ok(self.lookup(reference)?)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[tokio::test]
    async fn env_resolver_reads_only_env_refs() {
        std::env::set_var("CRAWLX_WORKER_TEST_CRED", "u:p");
        let r = EnvSecretResolver;
        let v = r
            .resolve(&CredentialRef("env://CRAWLX_WORKER_TEST_CRED".to_owned()))
            .await
            .unwrap();
        assert!(v.is_secret());
        assert_eq!(v.expose(), "u:p");
        assert!(matches!(
            r.lookup(&CredentialRef("vault://x".to_owned())),
            Err(SecretError::UnsupportedScheme { .. })
        ));
        assert!(matches!(
            r.lookup(&CredentialRef("env://CRAWLX_WORKER_TEST_MISSING".to_owned())),
            Err(SecretError::EnvUnset { .. })
        ));
    }
}
