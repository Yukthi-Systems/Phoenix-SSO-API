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


use routes::{health, user, chat_service, mail_service, file_service};
use actix_web::web::scope as actix_scope;
use actix_web::middleware::from_fn;
use actix_web::{App, HttpServer};
use std::env::var as env_var;
use actix_cors::Cors;

mod middleware;
mod database;
mod handlers;
mod models;
mod routes;
mod cache;
mod state;


#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let app_state = state::initialize().await;

    // Start the Actix web server
    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .wrap(Cors::default()
                .allowed_origin_fn(state::cors_allowed_origin_fn)
                .allowed_methods(vec!["GET", "POST", "PUT", "DELETE"])
                .supports_credentials()
                .allow_any_header()
                .max_age(420)
            )
            .service(
                actix_scope("/health")
                .service(health::api_health_check)
            )
            .service(
                actix_scope("/auth")
                .service(user::login)
                .service(
                    actix_scope("")
                    .wrap(from_fn(middleware::auth::auth_check))
                    .service(user::update_last_active)
                    .service(user::validate_session)
                    .service(user::validate_otp)
                    .service(user::resend_otp)
                    .service(user::logout)
                )
            )
            .service(
                actix_scope("/internal")
                .wrap(from_fn(middleware::auth::api_key_check))
                .service(chat_service::get_user_info_from_session_token)
                .service(file_service::get_user_info_from_session_token)
                .service(mail_service::clear_mail_service_login_cache)
                .service(user::delete_user_info)
            )
            .service(
                actix_scope("/mailbox")
                .wrap(from_fn(middleware::auth::post_login_api_key_check))
                .service(mail_service::validate_login_attempt)
            )
    })
    .bind(("0.0.0.0", 8686))?
    .workers(env_var("API_WORKERS_COUNT").unwrap_or("4".to_string()).parse().unwrap())
    .run().await
}
