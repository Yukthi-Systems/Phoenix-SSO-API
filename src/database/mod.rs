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


use deadpool_postgres::{
    PoolError as PgError,
    Pool as PgPool
};

pub mod geo_ip;
pub mod user;


// DB working state Check
pub async fn health_check(db_pool: &PgPool) -> Result<(), PgError> {
    // Simple query to check if the database is responsive
    let client = db_pool.get().await?;
    let _ = client.query("SELECT 1", &[]).await?;
    Ok(())
}
