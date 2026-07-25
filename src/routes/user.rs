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


use crate::database::user::{get_user_by_email, create_sso_session, delete_sso_session, update_sso_session_last_auth, update_sso_session_active_status};
use crate::handlers::{send_app_2fa_notification, send_sms_2fa_notification, send_email_2fa_notification};
use crate::cache::handler::{set_redis_cache, delete_redis_cache, get_redis_cache};
use actix_web::{delete, get, post, web, HttpResponse, HttpMessage, HttpRequest};
use actix_web::cookie::time::{self, OffsetDateTime};
use crate::models::errors::{ApiResponse, AppError};
use crate::state::{AppState, API_SETTINGS};
use actix_web::cookie::{Cookie, SameSite};
use crate::models::user::SessionUser;
use uuid::Uuid;


#[derive(serde::Deserialize)]
struct LoginRequest {
    user_email: String,
    password: String,
    device_details: serde_json::Value,
}


#[post("/login")]
pub async fn login(login_request: web::Json<LoginRequest>, state: web::Data<AppState>) -> ApiResponse {
    // Fetch user from DB based on email (Check if the Org is active or not and also check if the user is active or not)
    let user = get_user_by_email(&state.pg_pool, &login_request.user_email).await?;
    if user.is_none() {
        return Err(AppError::Unauthorized("User does not exist or is inactive, please check your email or contact support".to_string())); 
    }
    let user = user.unwrap();

    // Verify password
    if !user.verify_password(&login_request.password) {
        return Err(AppError::Unauthorized("Invalid password, please try again".to_string()));
    }

    // Create session and store in Redis with a TTL
    let is_2fa_enabled = user.is_app_2fa_enabled || user.is_sms_2fa_enabled || user.is_email_2fa_enabled;
    let session = SessionUser::create(&user, &login_request.password, &login_request.device_details, !is_2fa_enabled);
    let session_key = format!("session:{}", session.session_id);
    let exp_time = OffsetDateTime::now_utc() + time::Duration::days(28);
    let session_id = session.session_id.to_string();

    // If 2FA is enabled, we need to handle OTP verification before creating the session
    if is_2fa_enabled {
        // Create a session in Redis with a TTL of 10 minutes for OTP verification
        set_redis_cache(state.redis_cache.clone(), &session_key, &session, 10 * 60).await?;
        log::info!("User {} has 2FA enabled, OTP verification required. Session ID: {}", user.email, session.session_id);

        create_sso_session(&state.pg_pool, &session).await?;

        // Return response indicating that OTP verification is required
        return Ok(HttpResponse::Ok()
            .insert_header(("Cache-Control", "no-cache"))
            .cookie(
                Cookie::build("SSO-Session-ID", &session_id)
                    .path("/")
                    .http_only(true)
                    .secure(true)
                    .same_site(SameSite::Lax)
                    .expires(exp_time)
                    .domain(&API_SETTINGS.cookie_domain)
                    .finish(),
            )
            .json(serde_json::json!({
                "message": "OTP verification required",
                "expiration": exp_time.unix_timestamp(),
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "primary_phone": user.masked_primary_phone(),
                "secondary_email": user.masked_secondary_email(),
                "is_app_2fa_enabled": user.is_app_2fa_enabled,
                "is_sms_2fa_enabled": user.is_sms_2fa_enabled,
                "is_email_2fa_enabled": user.is_email_2fa_enabled,
                "organization_id": user.organization_id,
                "organization_name": user.organization_name
            })));
    }

    // Store session in Redis with a TTL of 3 Days (in seconds)
    set_redis_cache(state.redis_cache.clone(), &session_key, &session, 3 * 24 * 60 * 60).await?;

    // Create a session in the DB
    create_sso_session(&state.pg_pool, &session).await?;

    log::info!("User {} logged in successfully with session ID {}", user.email, session.session_id);

    // Set cookies, headers and return response
    Ok(HttpResponse::Ok()
        .insert_header(("Cache-Control", "no-cache"))
        .cookie(
            Cookie::build("SSO-Session-ID", &session_id)
                .path("/")
                .http_only(true)
                .secure(true)
                .same_site(SameSite::Lax)
                .expires(exp_time)
                .domain(&API_SETTINGS.cookie_domain)
                .finish(),
        )
        .json(serde_json::json!({
            "message": "Login successful",
            "expiration": exp_time.unix_timestamp(),
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "primary_phone": user.masked_primary_phone(),
            "secondary_email": user.masked_secondary_email(),
            "is_app_2fa_enabled": user.is_app_2fa_enabled,
            "is_sms_2fa_enabled": user.is_sms_2fa_enabled,
            "is_email_2fa_enabled": user.is_email_2fa_enabled,
            "organization_id": user.organization_id,
            "organization_name": user.organization_name
        })))
}


#[get("/session")]
pub async fn validate_session(request: HttpRequest) -> ApiResponse {
    // Get SessionUser from request extensions
    let ext = request.extensions();
    let session_user = ext.get::<SessionUser>().unwrap();

    // Check if the session is active
    if !session_user.is_active {
        return Err(AppError::Unauthorized("Session is inactive, please contact support".to_string()));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Session is valid",
        "email": session_user.email,
        "first_name": session_user.first_name,
        "last_name": session_user.last_name,
        "organization_id": session_user.organization_id,
        "organization_name": session_user.organization_name
    })))
}


#[post("/last-active")]
pub async fn update_last_active(request: HttpRequest, state: web::Data<AppState>) -> ApiResponse {
    // Get SessionUser from request extensions
    
    let ext = request.extensions();
    let session_user = ext.get::<SessionUser>().unwrap();

    // Check if the session is active
    if !session_user.is_active {
        return Err(AppError::Unauthorized("Session is inactive, please contact support".to_string()));
    }

    // Update the last active time
    update_sso_session_last_auth(&state.pg_pool, &session_user.session_id).await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Last active time updated successfully"
    })))
}


#[post("/otp/resend/{otp_type}")]
pub async fn resend_otp(request: HttpRequest, otp_type: web::Path<String>, state: web::Data<AppState>) -> ApiResponse {
    // Get SessionUser from request extensions
    let ext = request.extensions();
    let session_user = ext.get::<SessionUser>().unwrap();
    let otp_type = otp_type.into_inner();

    // Check if the session is active
    if session_user.is_active {
        return Err(AppError::BadRequest("Session is already active, no need to resend OTP".to_string()));
    }

    let user_info = get_user_by_email(&state.pg_pool, &session_user.email).await?;
    if user_info.is_none() {
        return Err(AppError::Unauthorized("User does not exist or is inactive, please check your email or contact support".to_string())); 
    }
    let user_info = user_info.unwrap();

    let otp_code = rand::random_range(100000..999999); // Generate a random 6-digit OTP code (Always 6 digits)
    let otp_key = format!("otp:{}:{}", session_user.session_id, otp_type);
    log::info!("Generated OTP code {} for user {}", otp_code, session_user.email);

    // Make sure the otp_type is valid
    match otp_type.as_str() {
        "app" => {
            set_redis_cache(state.redis_cache.clone(), &otp_key, &otp_code, 3 * 60).await?; // Store OTP in Redis with a TTL of 3 minutes
            log::info!("Resending OTP for App 2FA for user {}", session_user.email);
            send_app_2fa_notification(
                &state.rmq_settings,
                session_user.email.clone(),
                otp_code.to_string(),
                user_info.auth_app_fcm_tokens
            ).await;
        }
        "sms" => {
            set_redis_cache(state.redis_cache.clone(), &otp_key, &otp_code, 5 * 60).await?; // Store OTP in Redis with a TTL of 5 minutes
            log::info!("Resending OTP for SMS 2FA for user {}", session_user.email);
            send_sms_2fa_notification(
                &state.rmq_settings,
                user_info.primary_phone.clone(),
                otp_code.to_string()
            ).await;
        }
        "email" => {
            set_redis_cache(state.redis_cache.clone(), &otp_key, &otp_code, 7 * 60).await?; // Store OTP in Redis with a TTL of 7 minutes
            log::info!("Resending OTP for Email 2FA for user {}", session_user.email);
            send_email_2fa_notification(
                &state.rmq_settings,
                session_user.email.clone(),
                otp_code.to_string(),
                user_info.organization_name.clone(),
                format!("{} {}", &user_info.last_name.unwrap_or_default(), &user_info.first_name)
            ).await;
        }
        _ => {
            return Err(AppError::BadRequest("Invalid OTP type, must be one of 'app', 'sms', or 'email'".to_string()));
        }
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": format!("OTP resent successfully for {} 2FA", otp_type)
    })))
}


#[post("/otp/validate/{otp_type}/{otp}")]
pub async fn validate_otp(request: HttpRequest, path: web::Path<(String, String)>, state: web::Data<AppState>) -> ApiResponse {
    // Get SessionUser from request extensions
    let ext = request.extensions();
    let session_user = ext.get::<SessionUser>().unwrap();
    let (otp_type, otp) = path.into_inner();

    // Check if the session is active
    if session_user.is_active {
        return Err(AppError::BadRequest("Session is already active, no need to validate OTP".to_string()));
    }


    async fn validate_otp(otp_key: String, otp: String, state: web::Data<AppState>) -> Result<(), AppError> {
        // Get the OTP from Redis and compare with the provided OTP
        let stored_otp: Option<i32> = get_redis_cache(state.redis_cache.clone(), &otp_key).await?;
        if stored_otp.is_none() {
            return Err(AppError::BadRequest("OTP has expired or is invalid, please request a new OTP".to_string()));
        }
        let stored_otp = stored_otp.unwrap();

        // Compare the provided OTP with the stored OTP
        if stored_otp.to_string() != otp {
            delete_redis_cache(state.redis_cache.clone(), &otp_key).await?; // Delete the OTP from Redis if it doesn't match
            return Err(AppError::Unauthorized("Invalid OTP, please try again".to_string()));
        }

        Ok(())
    }

    // Get the OTP from Redis and compare with the provided OTP
    let otp_key = format!("otp:{}:{}", session_user.session_id, otp_type);

    // Make sure the otp_type is valid
    match otp_type.as_str() {
        "app" => {
            log::info!("Validating OTP for App 2FA for user {}", session_user.email);
            validate_otp(otp_key, otp, state.clone()).await?;
        }
        "sms" => {
            log::info!("Validating OTP for SMS 2FA for user {}", session_user.email);
            validate_otp(otp_key, otp, state.clone()).await?;
        }
        "email" => {
            log::info!("Validating OTP for Email 2FA for user {}", session_user.email);
            validate_otp(otp_key, otp, state.clone()).await?;
        }
        "backup" => {
            log::info!("Validating OTP for Backup 2FA for user {}", session_user.email);
            // For backup OTP, we need to make DB check to see if the provided OTP is valid and unused. If valid, mark it as used in the DB.
            return Err(AppError::NotImplemented("Backup 2FA is not implemented yet".to_string()));
        }
        _ => {
            return Err(AppError::BadRequest("Invalid OTP type, must be one of 'app', 'sms', 'email', or 'backup'".to_string()));
        }
    }

    // After successful OTP validation, we can mark the session as active and update the Redis cache and DB
    let mut updated_session_user = session_user.self_clone();
    updated_session_user.is_active = true;

    let session_key = format!("session:{}", updated_session_user.session_id);
    set_redis_cache(state.redis_cache.clone(), &session_key, &updated_session_user, 3 * 24 * 60 * 60).await?;
    update_sso_session_active_status(&state.pg_pool, &updated_session_user.session_id, true).await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": format!("OTP validated successfully for {} 2FA, session is now active", otp_type)
    })))
}


#[delete("/logout")]
pub async fn logout(request: HttpRequest, state: web::Data<AppState>) -> ApiResponse {
    // Get SessionUser from request extensions
    let ext = request.extensions();
    let session_user = ext.get::<SessionUser>().unwrap();

    // Check if the session is active
    if !session_user.is_active {
        return Err(AppError::Unauthorized("Session is inactive, please contact support".to_string()));
    }

    // Delete session from Redis
    let session_key = format!("session:{}", session_user.session_id);
    delete_redis_cache(state.redis_cache.clone(), &session_key).await?;

    // Delete session from DB
    delete_sso_session(&state.pg_pool, &session_user.session_id).await?;

    log::debug!("User {} logged out successfully and session {} deleted", session_user.email, session_user.session_id);

    // Build Cookie to delete on client side
    let mut cookie = Cookie::build("SSO-Session-ID", "")
        .path("/")
        .http_only(true)
        .domain(&API_SETTINGS.cookie_domain)
        .finish();

    cookie.make_removal();

    Ok(HttpResponse::Ok()
        .cookie(cookie)
        .json("Logged out successfully"))
}


#[delete("/user-info/{sso_token}")]
pub async fn delete_user_info(state: web::Data<AppState>, sso_token: web::Path<Uuid>) -> ApiResponse {
    let sso_token = sso_token.into_inner();
    
    // Delete session from Redis cache
    let key = format!("session:{}", sso_token);
    delete_redis_cache(state.redis_cache.clone(), &key).await?;

    // Delete session from DB
    delete_sso_session(&state.pg_pool, &sso_token).await?;
    
    Ok(HttpResponse::Ok().json("Session deleted successfully"))
}
