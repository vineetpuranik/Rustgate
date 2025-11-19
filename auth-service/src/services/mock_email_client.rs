use crate::domain::{Email, EmailClient};
use color_eyre::eyre::Result;

pub struct MockEmailClient;

#[async_trait::async_trait]
impl EmailClient for MockEmailClient {
    #[tracing::instrument(name = "Sending email", skip_all)]
    async fn send_email(&self, recipient: &Email, subject: &str, content: &str) -> Result<()> {
        // For now our mock email client will be simply logging the recipient, subject and content to standard output
        tracing::debug!(
            "Sending email to {} with subject {} and content {}",
            recipient.as_ref(),
            subject,
            content
        );

        Ok(())
    }
}
