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


use crate::models::initial::RmqSettings;
use serde::Serialize;
use reqwest::Client;


/// Function to send notification to RabbitMQ using HTTP API
pub async fn send_notification_to_rmq<T>(
    rmq_config: &RmqSettings,
    notification_type: &str,
    payload: &T,
) -> Result<(), Box<dyn std::error::Error>>
where
    T: Serialize,
{
    let client = Client::new();

    let rmq_url = format!(
        "https://{}/api/exchanges/{}/{}/publish",
        rmq_config.domain,
        rmq_config.virtual_host,
        rmq_config.exchange_name
    );

    let response = client.post(&rmq_url)
        .header("authorization", format!("Basic {}", rmq_config.auth_token))
        .header("content-type", "text/plain;charset=UTF-8")
        .body(serde_json::json!({
            "vhost": rmq_config.virtual_host,
            "name": rmq_config.exchange_name,
            "properties": {
                "delivery_mode": 2,
                "headers": {
                    "type": notification_type
                }
            },
            "routing_key": rmq_config.routing_key,
            "delivery_mode": "2",
            "payload": serde_json::to_string(payload)?,
            "payload_encoding": "string",
            "props": {}
        }).to_string())
        .send()
        .await?;

    if response.status().is_success() {
        log::info!("Notification sent successfully to RMQ");
        Ok(())
    } else {
        let error_text = response.text().await?;
        log::error!("Failed to send notification to RMQ: {}", error_text);
        Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Failed to send notification to RMQ: {}", error_text),
        )))
    }
}
