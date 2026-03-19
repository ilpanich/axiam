//! Mock email provider for testing.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use axiam_core::error::{AxiamError, AxiamResult};

use crate::message::EmailMessage;
use crate::provider::{EmailProvider, SendResult};

/// Recorded details of a sent email.
#[derive(Debug, Clone)]
pub struct SentEmail {
    pub from_name: String,
    pub from_email: String,
    pub reply_to: Option<String>,
    pub message: EmailMessage,
}

/// Mock email provider that records sent messages for test assertions.
pub struct MockProvider {
    sent: Arc<Mutex<Vec<SentEmail>>>,
    should_fail: bool,
}

impl MockProvider {
    /// Create a mock provider that succeeds on all sends.
    pub fn new() -> Self {
        Self {
            sent: Arc::new(Mutex::new(Vec::new())),
            should_fail: false,
        }
    }

    /// Create a mock provider that fails on all sends.
    pub fn failing() -> Self {
        Self {
            sent: Arc::new(Mutex::new(Vec::new())),
            should_fail: true,
        }
    }

    /// Get all sent messages.
    pub fn sent_messages(&self) -> Vec<SentEmail> {
        self.sent.lock().unwrap().clone()
    }

    /// Get the number of sent messages.
    pub fn sent_count(&self) -> usize {
        self.sent.lock().unwrap().len()
    }
}

impl Default for MockProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl EmailProvider for MockProvider {
    fn send(
        &self,
        from_name: &str,
        from_email: &str,
        reply_to: Option<&str>,
        message: &EmailMessage,
    ) -> Pin<Box<dyn Future<Output = AxiamResult<SendResult>> + Send + '_>>
    {
        let from_name = from_name.to_string();
        let from_email = from_email.to_string();
        let reply_to = reply_to.map(str::to_string);
        let message = message.clone();
        let should_fail = self.should_fail;
        let sent = self.sent.clone();

        Box::pin(async move {
            if should_fail {
                return Err(AxiamError::EmailDelivery(
                    "mock provider configured to fail".into(),
                ));
            }

            sent.lock().unwrap().push(SentEmail {
                from_name,
                from_email,
                reply_to,
                message,
            });

            Ok(SendResult {
                message_id: Some("mock-message-id".to_string()),
            })
        })
    }

    fn provider_name(&self) -> &'static str {
        "mock"
    }
}
