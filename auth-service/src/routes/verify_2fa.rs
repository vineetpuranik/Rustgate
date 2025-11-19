use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Email, LoginAttemptId, TwoFACode},
    utils::generate_auth_cookie,
};
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use serde::Deserialize;

#[tracing::instrument(name = "Verify 2FA", skip_all)]
pub async fn verify_2fa(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<Verify2FARequest>,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    // parse email from the input request
    let email = match Email::parse(request.email) {
        Ok(e) => e,
        Err(_) => return (jar, Err(AuthAPIError::InvalidCredentials)),
    };

    // parse login_attempt_id from the input request
    let login_attempt_id = match LoginAttemptId::parse(request.login_attempt_id) {
        Ok(l) => l,
        Err(_) => return (jar, Err(AuthAPIError::InvalidCredentials)),
    };

    // parse two_fa_code from the input request
    let two_fa_code = match TwoFACode::parse(request.two_fa_code) {
        Ok(t) => t,
        Err(_) => return (jar, Err(AuthAPIError::InvalidCredentials)),
    };

    // get write lock to two_fa_code_store
    let mut two_fa_code_store = state.two_fa_code_store.write().await;

    // call two_fa_code_store.get_code.
    // if the call fails return a AuthAPIError::IncorrectCredentials
    let code_tuple = match two_fa_code_store.get_code(&email).await {
        Ok((l, t)) => (l, t),
        Err(_) => return (jar, Err(AuthAPIError::IncorrectCredentials)),
    };

    // validate that the login_attempt_id and ut in the request body matches the values in code_tuple
    // if they do not match then return AuthAPIError::IncorrectCredentials

    if code_tuple.0 != login_attempt_id {
        return (jar, Err(AuthAPIError::IncorrectCredentials));
    }

    if code_tuple.1 != two_fa_code {
        return (jar, Err(AuthAPIError::IncorrectCredentials));
    }

    // remove 2fa code from the code store after successful authentication
    if let Err(e) = two_fa_code_store.remove_code(&email).await {
        return (jar, Err(AuthAPIError::UnexpectedError(e.into())));
    }

    // email, login attemptid, and 2fa are correct
    // as a result, we will update the cookie jar with a new JWT auth cookie
    let auth_cookie = match generate_auth_cookie(&email) {
        Ok(c) => c,
        Err(e) => return (jar, Err(AuthAPIError::UnexpectedError(e))),
    };
    let updated_jar = jar.add(auth_cookie);

    // send 200 response
    (updated_jar, Ok(StatusCode::OK.into_response()))
}

#[derive(Deserialize)]
pub struct Verify2FARequest {
    pub email: String,
    #[serde(rename = "loginAttemptId")]
    pub login_attempt_id: String,
    #[serde(rename = "2FACode")]
    pub two_fa_code: String,
}
