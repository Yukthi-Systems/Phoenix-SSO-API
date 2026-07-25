/*
 * Copyright (C) 2026 Yukthi Systems Private Limited
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 3 along with this program. If not, see
 * <https://www.gnu.org/licenses/>.
 */


use actix_web::{http::StatusCode, HttpResponse, ResponseError};
use deadpool_postgres::PoolError;
use redis::RedisError;
use serde::Serialize;
use std::fmt;


pub type ApiResponse = Result<HttpResponse, AppError>;


#[derive(Debug)]
pub enum AppError {
    DbPool(PoolError),
    Pg(tokio_postgres::Error),
    Redis(RedisError),
    SerDe(serde_json::Error),
    Unauthorized(String),
    BadRequest(String),
    NotImplemented(String),
    // Unprocessable(String),
    // NotFound(String),
    // Conflict(String),
    // Gone(String),
}


#[derive(Serialize)]
struct ErrorResp {
    error: String
}


// ------- Implementations ------- //


impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::DbPool(e) => write!(f, "DB: {}", e),
            AppError::Pg(e) => write!(f, "PostgreSQL: {}", e),
            AppError::Redis(e) => write!(f, "Redis: {}", e),
            AppError::SerDe(e) => write!(f, "JSON: {}", e),
            AppError::Unauthorized(s) => write!(f, "Unauthorized: {}", s),
            AppError::BadRequest(s) => write!(f, "Bad Request: {}", s),
            AppError::NotImplemented(s) => write!(f, "Not Implemented: {}", s),
            // AppError::NotFound(s) => write!(f, "Resource not found: {}", s),
            // AppError::Conflict(s) => write!(f, "Conflict: {}", s),
            // AppError::Gone(s) => write!(f, "It's gone: {}", s),
            // AppError::Unprocessable(s) => write!(f, "Unprocessable: {}", s),
        }
    }
}


impl From<PoolError> for AppError {
    fn from(e: PoolError) -> Self {
        AppError::DbPool(e)
    }
}


impl From<tokio_postgres::Error> for AppError {
    fn from(e: tokio_postgres::Error) -> Self {
        AppError::Pg(e)
    }
}


impl From<RedisError> for AppError {
    fn from(e: RedisError) -> Self {
        AppError::Redis(e)
    }
}


impl From<serde_json::Error> for AppError {
    fn from(e: serde_json::Error) -> Self {
        AppError::SerDe(e)
    }
}


impl ResponseError for AppError {
    fn status_code(&self) -> StatusCode {
        match self {
            AppError::DbPool(_) => StatusCode::FAILED_DEPENDENCY,
            AppError::Pg(_) => StatusCode::EXPECTATION_FAILED,
            AppError::Redis(_) => StatusCode::SERVICE_UNAVAILABLE,
            AppError::SerDe(_) => StatusCode::UNPROCESSABLE_ENTITY,
            AppError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppError::NotImplemented(_) => StatusCode::NOT_IMPLEMENTED,
            // AppError::NotFound(_) => StatusCode::NOT_FOUND,
            // AppError::Conflict(_) => StatusCode::CONFLICT,
            // AppError::Unprocessable(_) => StatusCode::UNPROCESSABLE_ENTITY,
            // AppError::Gone(_) => StatusCode::GONE,
        }
    }

    fn error_response(&self) -> HttpResponse {
        log::error!("Error occurred: {}", self);

        HttpResponse::build(self.status_code())
            .json(ErrorResp { error: self.to_string() })
    }
}


impl std::error::Error for AppError {}
