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


use serde::{Serialize, de::DeserializeOwned};
use redis::aio::MultiplexedConnection;
use redis::AsyncCommands;
use crate::models::errors::AppError;


type RedisResult<T> = Result<T, AppError>;


/// Set a key-value pair in Redis with an expiration time
pub async fn set_redis_cache<T>(
    conn: MultiplexedConnection,
    key: &str,
    value: &T,
    expiration_seconds: u64,
) -> RedisResult<()>
where
    T: Serialize,
{
    let mut redis_conn = conn;

    // Serialize the value to a JSON string
    let json_value: String = serde_json::to_string(value)?;

    Ok(redis_conn
        .set_ex(
            key,
            json_value,
            expiration_seconds
        )
        .await?
    )
}


/// Get a value from Redis by key
pub async fn get_redis_cache<T>(
    conn: MultiplexedConnection,
    key: &str
) -> RedisResult<Option<T>> 
where
    T: DeserializeOwned,
{
    let mut redis_conn = conn;

    // Get the JSON string from Redis
    let json_string: Option<String> = redis_conn.get(key).await?;

    if let Some(json) = json_string {
        let value: T = serde_json::from_str(&json)?;
        Ok(Some(value))
    } else {
        Ok(None)
    }
}


/// Delete a key from Redis
pub async fn delete_redis_cache(conn: MultiplexedConnection, key: &str) -> RedisResult<()> {
    let mut redis_conn = conn;
    Ok(redis_conn.del(key).await?)
}
