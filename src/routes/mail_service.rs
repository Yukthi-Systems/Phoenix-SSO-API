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


use crate::database::user::{create_mail_service_session, get_user_by_email};
use crate::handlers::send_login_attempt_notification;
use crate::handlers::session::fetch_mail_service_session_info;
use crate::database::geo_ip::check_if_geo_ip_is_allowed;
use actix_web::{HttpResponse, delete, post, web};
use crate::models::mail_svc::MailServiceSession;
use crate::cache::handler::{set_redis_cache, delete_redis_cache};
use crate::models::errors::ApiResponse;
use crate::state::AppState;


#[derive(serde::Deserialize)]
struct LoginRequest {
    email: String,
    ip_addr: String,
    domain: String,
}


// TODO: Clean up the endpoints and make them more modular and reusable. The current implementation is a bit monolithic


#[post("/login/attempt")]
pub async fn validate_login_attempt(state: web::Data<AppState>, body: web::Json<LoginRequest>) -> ApiResponse {
    let login_request = body.into_inner();

    // Generate a cache key based on the login request
    let cache_key = format!("mail_svc_login:{}:{}", login_request.email, login_request.ip_addr);

    // Check if the session info is present in the database
    let session_info = fetch_mail_service_session_info(&state, &login_request.email, &login_request.ip_addr, &login_request.domain, &cache_key).await?;

    // If session info is found, return a custom JSON
    if session_info.is_some() {
        // Since we handle the cache entry in the fetch_mail_service_session_info function, we don't need to handle it here
        if session_info.as_ref().unwrap().is_active {
            return Ok(HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "message": "Mail Service login session is valid"
            })));
        } else {
            return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                "success": false,
                "message": "Mail Service login session is not active"
            })));
        }
    }

    // If session is not found
    // - That means this is the first time the user is logging in from this IP address and email id
    // - We do all checks and validations here and return the response accordingly

    // 1. Get User Info from the database
    let user_info = get_user_by_email(&state.pg_pool, &login_request.email).await?;
    if user_info.is_none() {
        return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
            "success": false,
            "message": "Can be due to Password Expired or Inactive User"
        })));
    }
    let user_info = user_info.unwrap();
    let cache_time = user_info.session_timeout as u64;

    // 2. Check if the Mail Service is enabled for the user
    if !user_info.is_mail_service_enabled {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "success": false,
            "message": "Mail Service is not enabled for this user"
        })));
    }

    // 3. Check and Fetch the Geo & IP Info from the DB and Validate the IP Address and Geo Location
    let location_info = check_if_geo_ip_is_allowed(
        &state.pg_pool,
        &login_request.ip_addr,
        &user_info.restriction_policy
    ).await?;
    let (is_geo_ip_allowed, message) = location_info.validate_geo_ip();

    // If the Geo or IP is not allowed, return a Forbidden response + Cache the response in Redis for future requests
    if !is_geo_ip_allowed {
        // Cache the response in Redis for future requests
        let new_info = MailServiceSession::new(
            login_request.email.clone(),
            login_request.ip_addr.clone(),
            login_request.domain.clone(),
            Some(location_info),
            false
        );

        // Cache the response in Redis for future requests
        set_redis_cache(state.redis_cache.clone(), &cache_key, &new_info, cache_time).await?; // Cache for 30 minutes

        // Set the session info in the database
        create_mail_service_session(
            &state.pg_pool,
            &new_info,
            user_info.session_timeout
        ).await?;

        let notification_type = if message.contains("Geo location") {
            "MAILBOX_LOGIN_GEO_LOCATION_BLOCKED"
        } else {
            "MAILBOX_LOGIN_IP_BLOCKED"
        };

        let notification_title = if message.contains("Geo location") {
            "MailBox Login Attempt Blocked due to Geo Location Restriction"
        } else {
            "MailBox Login Attempt Blocked due to IP Restriction"
        };

        // Send a notification to the user about the login attempt
        tokio::spawn(
            send_login_attempt_notification(
                state.rmq_settings.clone(),
                login_request.email.clone(),
                login_request.ip_addr.clone(),
                user_info.auth_app_fcm_tokens.clone(),
                notification_type.to_string(),
                notification_title.to_string(),
                message.clone()
            )
        );

        // Return a Forbidden response
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "success": false,
            "message": message
        })));
    }

    // 4. Check if 2FA is enabled or not then proceed accordingly
    if user_info.is_app_2fa_enabled || user_info.is_sms_2fa_enabled || user_info.is_email_2fa_enabled {
        // TODO: Handle SMS + Email + TOTP 2FA Validation here
        // For now, we will handle any 2FA as App Based 2FA only

        let new_info = MailServiceSession::new(
            login_request.email.clone(),
            login_request.ip_addr.clone(),
            login_request.domain.clone(),
            Some(location_info),
            false
        );

        // Cache the response in Redis for future requests
        set_redis_cache(state.redis_cache.clone(), &cache_key, &new_info, 2 * 60).await?; // Cache for 2 minutes

        // Set the session info in the database
        create_mail_service_session(
            &state.pg_pool,
            &new_info,
            user_info.session_timeout
        ).await?;

        // Send a 2FA notification to the user about the login attempt
        tokio::spawn(
            // TODO: Based on the 2FA method enabled, send the notification accordingly
            send_login_attempt_notification(
                state.rmq_settings.clone(),
                login_request.email.clone(),
                login_request.ip_addr.clone(),
                user_info.auth_app_fcm_tokens.clone(),
                "MAILBOX_LOGIN_MFA_VERIFICATION".to_string(),
                "MailBox Login Attempt requires 2FA Validation".to_string(),
                "Please verify the login attempt to proceed".to_string()
            )
        );

        // Return a response indicating that 2FA is required
        return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
            "success": false,
            "message": "Mail Service login session requires 2FA validation"
        })));
    }

    // 5. Create a new session entry in the database and cache it for future requests
    // If there is no 2FA enabled, we can directly create a new session entry in the database and cache it for future requests
    let new_info = MailServiceSession::new(
        login_request.email.clone(),
        login_request.ip_addr.clone(),
        login_request.domain.clone(),
        Some(location_info),
        true
    );

    // Cache the response in Redis for future requests
    set_redis_cache(state.redis_cache.clone(), &cache_key, &new_info, cache_time).await?;

    // Set the session info in the database
    create_mail_service_session(
        &state.pg_pool,
        &new_info,
        user_info.session_timeout
    ).await?;

    // Send a notification to the user about the successful login attempt
    tokio::spawn(
        send_login_attempt_notification(
            state.rmq_settings.clone(),
            login_request.email.clone(),
            login_request.ip_addr.clone(),
            user_info.auth_app_fcm_tokens.clone(),
            "MAILBOX_LOGIN_SUCCESS".to_string(),
            "MailBox Login Attempt Successful".to_string(),
            "A new login attempt was successful from a new device or location. If not you, please disable the session immediately, and change your password.".to_string()
        )
    );

    // Return a response indicating that the login attempt is valid and successful
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Mail Service login session is valid and successful"
    })))
}


#[delete("/mail-service/clear")]
pub async fn clear_mail_service_login_cache(state: web::Data<AppState>, body: web::Json<LoginRequest>) -> ApiResponse {
    let login_request = body.into_inner();

    // Make a Cache Key
    let cache_key = format!("mail_svc_login:{}:{}", login_request.email, login_request.ip_addr);

    // Delete the cache entry
    delete_redis_cache(state.redis_cache.clone(), &cache_key).await?;

    Ok(HttpResponse::Ok().json("Mail Service login cache cleared successfully"))
}
