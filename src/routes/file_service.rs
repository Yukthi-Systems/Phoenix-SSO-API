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


use crate::database::user::{get_file_info_from_user_id, update_file_service_last_active_at};
use crate::handlers::session::fetch_user_session_info;
use actix_web::{get, web, HttpResponse};
use crate::models::errors::ApiResponse;
use crate::state::AppState;
use uuid::Uuid;


#[get("/file/user-info/{sso_token}")]
pub async fn get_user_info_from_session_token(state: web::Data<AppState>, sso_token: web::Path<Uuid>) -> ApiResponse {
    let sso_token = sso_token.into_inner();

    let session_info = fetch_user_session_info(&state, &sso_token).await?;
    if session_info.is_none() {
        return Ok(HttpResponse::NotFound().json("Session not found")); 
    }
    let session_info = session_info.unwrap();

    let file_info = get_file_info_from_user_id(&state.pg_pool, &session_info.email).await?;
    if file_info.is_none() {
        return Ok(HttpResponse::NotFound().json("File info not found for the user"));
    }
    let file_info = file_info.unwrap();

    // Spawn a background task to update the last active timestamp in the file service
    let email_clone = session_info.email.clone();
    let pg_pool_clone = state.pg_pool.clone();
    tokio::spawn(async move {
        if let Err(e) = update_file_service_last_active_at(&pg_pool_clone, &email_clone).await {
            log::error!("Failed to update file service last active at for user {}: {}", email_clone, e);
        }
    });

    Ok(HttpResponse::Ok().json(file_info)) 
}
