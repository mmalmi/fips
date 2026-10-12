//! This module implements the same features as the main crate, but using async io.

mod gateway;

#[cfg(feature = "aio_tokio")]
pub mod tokio;

use async_trait::async_trait;

use crate::RequestError;

pub use self::gateway::Gateway;

pub(crate) const MAX_RESPONSE_SIZE: usize = 1500;
pub(crate) const HEADER_NAME: &str = "SOAPAction";

/// Trait to allow abstracting over `tokio` and `async-std`.
#[async_trait]
pub trait Provider {
    /// Send an async request over the executor.
    async fn send_async(url: &str, action: &str, body: &str) -> Result<String, RequestError>;
}

/// An asynchronous request retaining the provider's instance state.
pub type RequestFuture<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, RequestError>> + Send + 'a>>;

/// Instance-backed SOAP transport. Discovery stores this provider in the gateway,
/// so later mapping, renewal and deletion requests use the same host policy.
pub trait RequestProvider {
    /// Send a SOAP request without replacing the configured transport on failure.
    fn send_request<'a>(
        &'a self,
        url: &'a str,
        action: &'a str,
        body: &'a str,
    ) -> RequestFuture<'a>;
}

// Legacy static providers retain their existing public implementation contract.
impl<P: Provider> RequestProvider for P {
    fn send_request<'a>(
        &'a self,
        url: &'a str,
        action: &'a str,
        body: &'a str,
    ) -> RequestFuture<'a> {
        P::send_async(url, action, body)
    }
}
