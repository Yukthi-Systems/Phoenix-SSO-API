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


use crate::models::initial::{ApiSettings, AppSettings, PgSettings, RedisSettings, RmqSettings};
use deadpool_postgres::{Manager, RecyclingMethod, Pool as PgPool};
use redis::{Client, aio::MultiplexedConnection};
use native_tls::{Certificate, TlsConnector};
use deadpool::{managed::Timeouts, Runtime};
use postgres_native_tls::MakeTlsConnector;
use actix_web::web::Data as webData;
use tokio_postgres::Config;
use std::sync::LazyLock;
use std::time::Duration;
use std::fs;


pub struct AppState {
    pub pg_pool: PgPool,
    pub redis_cache: MultiplexedConnection,
    pub rmq_settings: RmqSettings,
}


pub static API_SETTINGS: LazyLock<ApiSettings> = LazyLock::new(|| {
    ApiSettings::from_env()
});


async fn warm_pool(pool: &PgPool, pg: &PgSettings) {
    // Warm pool to avoid first-hit latency
    if !pg.warm_pool {
        // Return early if warm pool is not enabled
        return;
    }

    let warm_n = pg.max_pool_size.min(pg.warm_pool_size);
    let mut ok = 0;

    for _ in 0..warm_n {
        match pool.get().await {
            Ok(client) => {
                let _ = client.simple_query("SELECT 1").await;
                ok += 1;
            }
            Err(_) => {
                log::warn!("Pool warm-up: failed to get a connection");
            }
        }
    }

    // Log the warm-up results
    if ok == 0 {
        log::warn!("Pool warm-up failed, all attempts to get a connection were unsuccessful: {warm_n}");
    } else {
        log::info!("Pool warm-up: {ok} conns warmed up out of {warm_n}. Success rate: {:.2}%", ok as f64 / warm_n as f64 * 100.0);
    }
}


fn build_pg_config(settings: &PgSettings) -> Config {
    // Initialize the Postgres configuration
    let mut cfg: Config = settings.url.parse::<Config>().expect("invalid POSTGRES_DB_URL");
    cfg.application_name("rust-api");
    cfg.connect_timeout(Duration::from_secs(settings.conn_timeout));

    cfg
}


fn tls_builder_from_settings(settings: &PgSettings) -> TlsConnector {
    log::info!("Postgres SSL settings: accept_invalid_certs={}, accept_invalid_hostnames={}, root_cert_path={:?}",
        settings.ssl_accept_invalid_certs,
        settings.ssl_accept_invalid_hostnames,
        settings.ssl_root_cert_path
    );

    // Build a TLS connector based on the provided settings
    let mut tls_builder = TlsConnector::builder();
    
    // Configure the TLS connector to accept or reject invalid certificates and hostnames based on the settings
    tls_builder.danger_accept_invalid_certs(settings.ssl_accept_invalid_certs);
    tls_builder.danger_accept_invalid_hostnames(settings.ssl_accept_invalid_hostnames);

    // If a root certificate path is provided, read the certificate and add it to the TLS connector
    if let Some(cert_path) = &settings.ssl_root_cert_path {
        let cert_data = fs::read(cert_path)
            .unwrap_or_else(|err| panic!("failed to read PG_SSL_ROOT_CERT_PATH at {}: {}", cert_path, err));
        let cert = Certificate::from_pem(&cert_data)
            .unwrap_or_else(|err| panic!("invalid PEM certificate at PG_SSL_ROOT_CERT_PATH ({}): {}", cert_path, err));
        tls_builder.add_root_certificate(cert);
    }

    // Build the TLS connector and return it, panicking if the build fails
    tls_builder.build().expect("failed to build postgres TLS connector")
}


fn init_pg_pool(pg_settings: &PgSettings) -> PgPool {
    // Get the Postgres base configuration
    let cfg: Config = build_pg_config(pg_settings);

    // Build a TLS connector so sslmode from the connection URL can be honored.
    // This supports both SSL and non-SSL URLs while avoiding hardcoded NoTls.
    let tls = MakeTlsConnector::new(tls_builder_from_settings(pg_settings));

    let mgr = Manager::from_config(
        cfg,
        tls,
        deadpool_postgres::ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        },
    );

    let pool = PgPool::builder(mgr)
        .max_size(pg_settings.max_pool_size)
        .runtime(Runtime::Tokio1)
        .timeouts(Timeouts {
            // how long to wait for an idle connection from the pool
            wait: Some(Duration::from_secs(pg_settings.wait_timeout)),
            // how long to spend creating a new connection (if pool can grow)
            create: Some(Duration::from_secs(pg_settings.new_connection_timeout)),
            // how long to spend recycling/validating a connection
            recycle: Some(Duration::from_secs(pg_settings.recycle_timeout)),
        })
        .build()
        .expect("failed to build pg pool");

    log::info!("Postgres pool initialized (max_pool_size={})", pg_settings.max_pool_size);
    pool
}


async fn init_redis(redis_settings: &RedisSettings) -> MultiplexedConnection {
    let client = Client::open(redis_settings.url.clone()).expect("Failed to create Redis client");

    let mut conn = client.get_multiplexed_async_connection().await.expect("Failed to connect to Redis");

    let pong: String = redis::cmd("PING").query_async(&mut conn).await.expect("Failed to ping Redis");
    if pong != "PONG" {
        log::warn!("Unexpected PING response from Redis: {}", pong);
        panic!("Failed to connect to Redis");
    }

    conn
}


pub fn cors_allowed_origin_fn(origin: &actix_web::http::header::HeaderValue, _: &actix_web::dev::RequestHead) -> bool {
    let origin_str = origin.to_str().unwrap_or("");
    let allowed_origins = &API_SETTINGS.allowed_origins;

    if allowed_origins.iter().any(|item| item == "*") {
        return true;
    }

    allowed_origins.iter().any(|item| item == origin_str)
}


pub async fn initialize() -> webData<AppState> {
    // Preparing to start the server by collecting environment variables
    let app_settings: AppSettings = AppSettings::from_env();

    if app_settings.enable_logging {
        let _ = env_logger::try_init(); // Initialize the logger to log all the logs
        log::info!("Starting the server by initializing the application state");
    }

    // Initialize the Postgres client
    let postgres_state = init_pg_pool(&app_settings.pg_settings);

    // Warm up the connection pool if enabled
    warm_pool(&postgres_state, &app_settings.pg_settings).await;

    // Initialize Redis client
    let redis_client = init_redis(&app_settings.redis_settings).await;

    // Wrap the state of the application and share it
    webData::new(AppState {
        pg_pool: postgres_state,
        redis_cache: redis_client,
        rmq_settings: app_settings.rmq_settings,
    })
}
