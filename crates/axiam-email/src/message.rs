//! Email message type ready for delivery.

/// An email message ready for delivery via any provider.
#[derive(Debug, Clone)]
pub struct EmailMessage {
    /// Recipient email address.
    pub to: String,
    /// Email subject line.
    pub subject: String,
    /// HTML body (optional — at least one of html/text must be set).
    pub html_body: Option<String>,
    /// Plain-text body (optional — at least one of html/text must be set).
    pub text_body: Option<String>,
}

impl EmailMessage {
    /// Returns `true` if the message has at least one body variant.
    pub fn has_body(&self) -> bool {
        self.html_body.is_some() || self.text_body.is_some()
    }
}
