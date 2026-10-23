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


use crate::database::user::{get_sso_session, get_mail_service_session};
use crate::cache::handler::{get_redis_cache, set_redis_cache};
use crate::models::mail_svc::MailServiceSession;
use crate::state::{AppState, API_SETTINGS};
use crate::models::user::SessionUser;
use crate::models::errors::AppError;
use reqwest::Client as HttpClient;


/// Fetches user session info based on the provided SSO token.
/// 1. It attempts to retrieve the session information from the Redis cache using the SSO token as the key.
/// 2. If the session information is found in the cache, it returns the cached session information.
/// 3. If the session information is not found in the cache, it queries the database for the session information using the SSO token.
/// 4. If the session information is found in the database, it stores the session information in the Redis cache with a TTL of 3 days and returns the session information.
/// 5. If the session information is not found in both the cache and the database, it returns None.
pub async fn fetch_user_session_info(app_state: &AppState, sso_token: &uuid::Uuid) -> Result<Option<SessionUser>, AppError> {
    // Fetch session from cache or if not found in cache, fetch from DB and set in cache (with a TTL)
    let key = format!("session:{}", sso_token);
    let user: Option<SessionUser> = get_redis_cache(app_state.redis_cache.clone(), &key).await?;

    // Check if session exists in cache, if yes return the session info
    if let Some(user) = user {
        return Ok(Some(user));
    } else {
        // Check the session in DB as a fallback (in case of cache miss or Redis failure)
        let db_session = get_sso_session(&app_state.pg_pool, sso_token).await?;

        // If session exists in DB, set it in cache and return the session info
        if let Some(db_session) = db_session {
            // Set the session in Redis cache with a TTL of 3 days (in seconds)
            set_redis_cache(app_state.redis_cache.clone(), &key, &db_session, 3 * 24 * 60 * 60).await?;

            return Ok(Some(db_session));
        }
    }

    Ok(None)
}


pub async fn fetch_mail_service_session_info(app_state: &AppState, email: &str, ip_addr: &str, domain: &str, cache_key: &str) -> Result<Option<MailServiceSession>, AppError> {
    // Fetch session from cache or if not found in cache, fetch from DB and set in cache (with a TTL)
    let user: Option<MailServiceSession> = get_redis_cache(app_state.redis_cache.clone(), cache_key).await?;

    // Check if session exists in cache, if yes return the session info
    if let Some(user) = user {
        return Ok(Some(user));
    } else {
        // Check the session in DB as a fallback (in case of cache miss or Redis failure)
        let db_session = get_mail_service_session(&app_state.pg_pool, email, ip_addr, domain).await?;

        
        // If session exists in DB, set it in cache and return the session info
        if let Some(db_session) = db_session {
            // Set the session in Redis cache with a TTL of 30 minutes (in seconds)
            set_redis_cache(app_state.redis_cache.clone(), cache_key, &db_session, 30 * 60).await?;

            return Ok(Some(db_session));
        }
    }

    Ok(None)
}


pub async fn validate_captcha(recaptcha_token: &str) -> Result<bool, AppError> {
    // Implement the logic to validate the reCAPTCHA token using the Google reCAPTCHA Enterprise API
    // Return Ok(true) if the token is valid, otherwise return Ok(false)
    // You may need to make an HTTP request to the Google reCAPTCHA API and handle the response

    // Placeholder implementation (replace with actual validation logic)
    if recaptcha_token.is_empty() {
        return Ok(false);
    }

    Ok(true)
}


pub async fn is_password_breached(email: &str, password: &str) -> Result<bool, AppError> {
    let client = HttpClient::new();

    let pld_url = format!("{}/createAssessment", API_SETTINGS.google_pld_api_base_url);

    let response = client.post(&pld_url)
        .header("Content-Type", "application/json; charset=utf-8")
        .header("X-API-Key", API_SETTINGS.google_pld_api_key.clone())
        .json(&serde_json::json!({
            "email": email,
            "password": password
        }))
        .send()
        .await
        .map_err(|err| AppError::Unauthorized(
            format!("Failed to call Password Leak Detection API: {}", err)
        ))?;

    if !response.status().is_success() {
        return Err(AppError::Unauthorized(
            format!("Password Leak Detection API returned an error: {}", response.status())
        ));
    }

    let response_body: serde_json::Value = response.json().await.map_err(|err| AppError::Unauthorized(
        format!("Failed to parse Password Leak Detection API response: {}", err)
    ))?;

    // Example response from the Password Leak Detection API: {"leakedStatus": "LEAKED | NO_STATUS"}
    if let Some(leaked_status) = response_body.get("leakedStatus").and_then(|v| v.as_str()) {
        // If the leakedStatus is "LEAKED", the password has been leaked
        if leaked_status == "LEAKED" {
            return Ok(true);
        }

        // Only "NO_STATUS" indicates that the password has not been leaked
        if leaked_status == "NO_STATUS" {
            return Ok(false);
        }
    }

    // If the leakedStatus is not "LEAKED" or "NO_STATUS", consider it as potentially leaked
    Ok(true)
}
