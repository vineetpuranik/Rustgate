use axum::{
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    serve::Serve,
    Json, Router,
};
use domain::AuthAPIError;
use redis::Client;
use redis::RedisResult;
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::error::Error;
use tower_http::{cors::CorsLayer, services::ServeDir, trace::TraceLayer};

pub mod domain;
pub mod routes;
pub mod services;
pub mod utils;

use crate::{
    routes::*,
    utils::{make_span_with_request_id, on_request, on_response},
};
use app_state::AppState;

//This struct encapsulates our application related logic
pub struct Application {
    server: Serve<Router, Router>,
    // address is exposed as a public field.
    // this makes it possible to access address in tests
    pub address: String,
}

impl Application {
    pub async fn build(app_state: AppState, address: &str) -> Result<Self, Box<dyn Error>> {
        // Allow the app service(running on our local machine and in production) to call the auth service
        let allowed_origins = [
            "http://localhost:8000".parse()?,
            // TODO: Replace [YOUR_DROPLET_IP] with your Droplet IP address
            "http://206.189.72.134:8000".parse()?,
        ];

        let cors = CorsLayer::new()
            // Allow GET and POST requests
            .allow_methods([Method::GET, Method::POST])
            // Allow cookies to be included in requests
            .allow_credentials(true)
            .allow_origin(allowed_origins);

        // Move the Router definition from main.rs here
        let router = Router::new()
            .nest_service("/", ServeDir::new("assets"))
            .route("/signup", post(signup))
            .route("/login", post(login))
            .route("/logout", post(logout))
            .route("/verify-2fa", post(verify_2fa))
            .route("/verify-token", post(verify_token))
            .with_state(app_state)
            .layer(cors) // Add CORS config to our Axum router
            .layer(
                // Add a TraceLayer for HTTP request to enable detailed tracing.
                // This layer will create spans for each request using the make_span_with_request_id function
                // and log events at the start and end of each request using on_request and on_response functions.
                TraceLayer::new_for_http()
                    .make_span_with(make_span_with_request_id)
                    .on_request(on_request)
                    .on_response(on_response),
            );

        let listener = tokio::net::TcpListener::bind(address).await?;
        let address = listener.local_addr()?.to_string();
        let server = axum::serve(listener, router);
        // Create a new application instance and return it
        Ok(Application { server, address })
    }

    pub async fn run(self) -> Result<(), std::io::Error> {
        tracing::info!("listening on {}", &self.address);
        self.server.await
    }
}

pub mod app_state {
    use std::sync::Arc;
    use tokio::sync::RwLock;

    use crate::domain::{BannedTokenStore, EmailClient, TwoFACodeStore, UserStore};

    // we will use a type alias for representing Arc<RwLock<Box<dyn UserStore>>>
    // Wrapping the user store in an Arc allows shared ownership of the underlying store across threads.
    // Calling clone on an Arc produces a new Arc instance which points to the same allocation on the heap as source Arc.
    // Instead of copying the reference data, the reference count is incremented.

    // Arc only provides an immutable reference to the underlying data (user store in our case)
    // It mutation were allowed, it would introduce possibility of data races and inconsistencies between threads.
    // However, route handlers need mutable access to user store to add / remove users from user store.
    // To achieve this we need a synchronization primitive and we will be using the RwLock provided by tokio.

    // In Summary, by wrapping the user store in tokio's RwLock smart pointer, the user store can be safely mutated across threads.
    // By wrapping RwLock<Box<dyn UserStore>> in an Arc smart pointer, the underlying data can be shared across threads while maintaining a single source of truth.
    pub type UserStoreType = Arc<RwLock<Box<dyn UserStore + Send + Sync>>>;
    pub type BannedTokenStoreType = Arc<RwLock<dyn BannedTokenStore + Send + Sync>>;
    pub type TwoFACodeStoreType = Arc<RwLock<dyn TwoFACodeStore + Send + Sync>>;
    pub type EmailClientType = Arc<RwLock<dyn EmailClient + Send + Sync>>;

    #[derive(Clone)]
    // AppState derives the Clone trait
    // Axum clones th application state before passing it into route handlers
    // This ensures that each request has a consistent snapshot of the state without causing race or inconsistencies.
    pub struct AppState {
        pub user_store: UserStoreType,
        pub banned_token_store: BannedTokenStoreType,
        pub two_fa_code_store: TwoFACodeStoreType,
        pub email_client: EmailClientType,
    }

    impl AppState {
        pub fn new(
            user_store: UserStoreType,
            banned_token_store: BannedTokenStoreType,
            two_fa_code_store: TwoFACodeStoreType,
            email_client: EmailClientType,
        ) -> Self {
            Self {
                user_store,
                banned_token_store,
                two_fa_code_store,
                email_client,
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

impl IntoResponse for AuthAPIError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthAPIError::InvalidCredentials => (StatusCode::BAD_REQUEST, "Invalid Credentials"),
            AuthAPIError::UserAlreadyExists => (StatusCode::CONFLICT, "User already exists"),
            AuthAPIError::IncorrectCredentials => {
                (StatusCode::UNAUTHORIZED, "IncorrectCredentials")
            }
            AuthAPIError::UnexpectedError => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Unexpected error")
            }
            AuthAPIError::InvalidToken => (StatusCode::UNAUTHORIZED, "InvalidToken"),
            AuthAPIError::MissingToken => (StatusCode::BAD_REQUEST, "MissingToken"),
        };

        let body = Json(ErrorResponse {
            error: error_message.to_string(),
        });

        (status, body).into_response()
    }
}

// Add get_postgres_pool helper function
pub async fn get_postgres_pool(url: &str) -> Result<PgPool, sqlx::Error> {
    // Create a new PostgreSQL connection pool
    PgPoolOptions::new().max_connections(5).connect(url).await
}

// Add get_redis_client helper function
pub fn get_redis_client(redis_hostname: String) -> RedisResult<Client> {
    let redis_url = format!("redis://{}/", redis_hostname);
    redis::Client::open(redis_url)
}
