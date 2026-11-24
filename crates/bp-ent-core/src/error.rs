//! One error type for every service, mapped to HTTP without leaking internals.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// No valid credentials.
    #[error("unauthorized")]
    Unauthorized,
    /// Valid credentials, not allowed.
    #[error("forbidden")]
    Forbidden,
    /// Missing, or in another tenant (indistinguishable on purpose).
    #[error("not found")]
    NotFound,
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("invalid request: {0}")]
    Invalid(String),
    #[error("too many requests")]
    TooManyRequests,
    /// An upstream service (IdP, KMS, mail, Stripe) failed.
    #[error("upstream unavailable")]
    Upstream(#[source] anyhow::Error),
    #[error("internal error")]
    Internal(#[source] anyhow::Error),
}

impl Error {
    pub fn invalid(msg: impl Into<String>) -> Self {
        Self::Invalid(msg.into())
    }
    pub fn conflict(msg: impl Into<String>) -> Self {
        Self::Conflict(msg.into())
    }
    pub fn internal(e: impl Into<anyhow::Error>) -> Self {
        Self::Internal(e.into())
    }
    pub fn upstream(e: impl Into<anyhow::Error>) -> Self {
        Self::Upstream(e.into())
    }

    pub fn status(&self) -> StatusCode {
        match self {
            Error::Unauthorized => StatusCode::UNAUTHORIZED,
            Error::Forbidden => StatusCode::FORBIDDEN,
            Error::NotFound => StatusCode::NOT_FOUND,
            Error::Conflict(_) => StatusCode::CONFLICT,
            Error::Invalid(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Error::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
            Error::Upstream(_) => StatusCode::BAD_GATEWAY,
            Error::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Error::Unauthorized => "unauthorized",
            Error::Forbidden => "forbidden",
            Error::NotFound => "not_found",
            Error::Conflict(_) => "conflict",
            Error::Invalid(_) => "invalid",
            Error::TooManyRequests => "rate_limited",
            Error::Upstream(_) => "upstream",
            Error::Internal(_) => "internal",
        }
    }
}

impl From<sqlx::Error> for Error {
    fn from(e: sqlx::Error) -> Self {
        match &e {
            sqlx::Error::RowNotFound => Error::NotFound,
            sqlx::Error::Database(db) => match db.code().as_deref() {
                // unique_violation
                Some("23505") => Error::Conflict("already exists".into()),
                // foreign_key_violation: the referenced row is missing (or in another tenant)
                Some("23503") => Error::Invalid("referenced item does not exist".into()),
                // check_violation / not_null_violation
                Some("23514") | Some("23502") => Error::Invalid("value not allowed".into()),
                // insufficient_privilege: a row-level security WITH CHECK refused the write
                Some("42501") => Error::NotFound,
                _ => Error::Internal(e.into()),
            },
            _ => Error::Internal(e.into()),
        }
    }
}

impl From<anyhow::Error> for Error {
    fn from(e: anyhow::Error) -> Self {
        Error::Internal(e)
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let status = self.status();
        let code = self.code();
        let body = match &self {
            Error::Internal(cause) | Error::Upstream(cause) => {
                // The cause goes to the log under an id; the caller only gets the id.
                let id = uuid::Uuid::new_v4();
                tracing::error!(error_id = %id, code, cause = format!("{cause:#}"), "request failed");
                json!({ "error": { "code": code, "message": self.to_string(), "id": id } })
            }
            _ => json!({ "error": { "code": code, "message": self.to_string() } }),
        };
        (status, Json(body)).into_response()
    }
}
