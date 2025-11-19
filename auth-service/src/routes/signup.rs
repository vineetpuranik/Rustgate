use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Email, Password, User, UserStoreError},
};

// Use axum's state extractor to pass in AppState
// The #[tracing::instrument] attribute macro implements the signup function for tracing.
// The span is named as Signup, all arguments are skipped from being recorded in the trace and we are capturing errors with Debug formatting if they occur.
#[tracing::instrument(name = "Signup", skip_all)]
pub async fn signup(
    State(state): State<AppState>,
    Json(request): Json<SignupRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    let email =
        Email::parse(request.email.clone()).map_err(|_| AuthAPIError::InvalidCredentials)?;
    let password =
        Password::parse(request.password.clone()).map_err(|_| AuthAPIError::InvalidCredentials)?;

    // create a new User instance using data int the request
    let new_user = User {
        email: email,
        password: password,
        requires_2fa: request.requires_2fa,
    };

    // get exclusive write access to user store and add new_user to user store
    let mut user_store = state.user_store.write().await;

    // early return AuthAPIError::UserAlreadyExists if add_user returns UserStoreError::UserAlreadyExists
    // early return AuthAPIError::UnexpectedError if add_user fails
    match user_store.add_user(new_user).await {
        Ok(()) => {}
        Err(UserStoreError::UserAlreadyExists) => return Err(AuthAPIError::UserAlreadyExists),
        Err(e) => return Err(AuthAPIError::UnexpectedError(e.into())),
    };

    let response = Json(SignupResponse {
        message: "User created successfully!".to_string(),
    });

    Ok((StatusCode::CREATED, response))
}

#[derive(Deserialize)]
pub struct SignupRequest {
    pub email: String,
    pub password: String,
    #[serde(rename = "requires2FA")]
    pub requires_2fa: bool,
}

#[derive(Serialize)]
pub struct SignupResponse {
    pub message: String,
}
