use color_eyre::eyre::Report;
use thiserror::Error;

// the thiserror crate simplifies the creation of custom error types by providing the #[derive(Error)] attribute macro,
// which automatically implements the Error trait for the AuthAPIError enum.
// Each variant of the enum has a custom Display error message specified by the #[error(...)] attribute.
#[derive(Debug, Error)]
pub enum AuthAPIError {
    #[error("User already exists")]
    UserAlreadyExists,
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Incorrect credentials")]
    IncorrectCredentials,
    #[error("Missing token")]
    MissingToken,
    #[error("Invalid token")]
    InvalidToken,
    // The UnexpectedError variant uses eyre::Report to wrap underlying errors and the #[source] attribute indicates that Report is the source of the error.
    // This setup makes it easier to diagnose and debug unexpected or complex errors by capturing rich context and detailed information about the errors.
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}
