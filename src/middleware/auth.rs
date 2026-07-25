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


use actix_web::{
    dev::{
        ServiceRequest,
        ServiceResponse
    },
    body::MessageBody,
    middleware::Next,
    HttpResponse,
    HttpMessage,
    Error,
    web,
};
use crate::{
    state::AppState,
    state::API_SETTINGS,
    models::user::SessionUser,
    cache::handler::{get_redis_cache, set_redis_cache},
    database::user::get_sso_session,
};


/// Check for valid session based on Session-ID cookie and x-csrf-token header
/// Inserts SessionUser into request extensions if valid
/// Returns true if valid, false otherwise
async fn session_check(req: &ServiceRequest) -> bool {
    // Look for Session-ID cookie and x-csrf-token header
    let session_id = req
        .cookie("SSO-Session-ID")
        .map(|c| c.value().to_string());

    // If session ID is missing, fail
    if session_id.is_none() {
        return false;
    }
    let session_id: uuid::Uuid = session_id.unwrap().parse().unwrap();

    // Check cache for session
    let state = req.app_data::<web::Data<AppState>>().unwrap();
    let key = format!("session:{}", session_id);

    // Fetch session data from Redis cache
    let user: Option<SessionUser> = get_redis_cache(state.redis_cache.clone(), &key).await.unwrap();

    // If session exists in cache, insert SessionUser into request extensions
    if let Some(user) = user {
        // Insert user into request extensions for further use
        req.extensions_mut().insert(user);

        return true;
    } else {
        // Check the session in DB as a fallback (in case of cache miss or Redis failure)
        let db_session = get_sso_session(&state.pg_pool, &session_id).await.unwrap();
        log::info!("Session {} not found in cache, checked DB: {}", session_id, db_session.is_some());

        // If session exists in DB, insert SessionUser into request extensions and also set it in cache for future requests
        if let Some(db_session) = db_session {
            // Set the session in Redis cache with a TTL of 3 days (in seconds)
            let _ = set_redis_cache(state.redis_cache.clone(), &key, &db_session, 3 * 24 * 60 * 60).await;

            // Insert user into request extensions for further use
            req.extensions_mut().insert(db_session);

            return true;
        }

        return false;
    }
}


/// Authentication middleware
/// Checks for valid session and optionally API key
/// Short-circuits with 401 Unauthorized if checks fail
/// Otherwise calls the next service in the chain
pub async fn auth_check<B>(req: ServiceRequest, next: Next<B>) -> Result<ServiceResponse, Error>
    where B: MessageBody + 'static
{
    // See if session is valid
    if !session_check(&req).await {
        // Short-circuit and return 401 Unauthorized
        let resp = HttpResponse::Unauthorized()
            .append_header(("content-type", "text/plain; charset=utf-8"))
            .body("Unauthorized: invalid session");

        // Convert into a ServiceResponse with a boxed body to satisfy types
        return Ok(req.into_response(resp).map_into_boxed_body());
    }

    // authorized -> call the next service
    let res = next.call(req).await?;
    Ok(res.map_into_boxed_body())
}


/// API Key header check middleware for internal API routes (Normal Internal API)
pub async fn api_key_check<B>(req: ServiceRequest, next: Next<B>) -> Result<ServiceResponse, Error>
    where B: MessageBody + 'static
{
    // Check for x-api-key header
    let api_key = req.headers().get("x-api-key").and_then(|h| h.to_str().ok());

    if api_key != Some(&API_SETTINGS.basic_api_key) {
        log::warn!("API key check failed for request {} {}", req.method(), req.path());

        // Short-circuit and return 401 Unauthorized
        let resp = HttpResponse::Unauthorized()
            .append_header(("content-type", "text/plain; charset=utf-8"))
            .body("Unauthorized: Invalid API key");

        // Convert into a ServiceResponse with a boxed body to satisfy types
        return Ok(req.into_response(resp).map_into_boxed_body());
    }

    // authorized -> call the next service
    let res = next.call(req).await?;
    Ok(res.map_into_boxed_body())
}


/// API Key header check middleware for internal API routes (MailBox Check at Post Login Script)
pub async fn post_login_api_key_check<B>(req: ServiceRequest, next: Next<B>) -> Result<ServiceResponse, Error>
    where B: MessageBody + 'static
{
    // Check for x-api-key header
    let api_key = req.headers().get("x-api-key").and_then(|h| h.to_str().ok());

    if api_key != Some(&API_SETTINGS.mailbox_api_key) {
        log::warn!("API key check failed for request {} {}", req.method(), req.path());

        // Short-circuit and return 401 Unauthorized
        let resp = HttpResponse::Unauthorized()
            .append_header(("content-type", "text/plain; charset=utf-8"))
            .body("Unauthorized: Invalid API key");

        // Convert into a ServiceResponse with a boxed body to satisfy types
        return Ok(req.into_response(resp).map_into_boxed_body());
    }

    // authorized -> call the next service
    let res = next.call(req).await?;
    Ok(res.map_into_boxed_body())
}
