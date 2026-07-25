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
use chrono::Datelike;

pub mod encryption;
pub mod session;
mod rmq;


pub async fn send_login_attempt_notification(
    rmq_settings: RmqSettings,
    email: String,
    ip_addr: String,
    fcm_tokens: Vec<String>,
    notification_type: String,
    notification_title: String,
    notification_message: String,
) {
    for token in &fcm_tokens {
        // Send notification to RabbitMQ (In background)
        rmq::send_notification_to_rmq(
            &rmq_settings,
            "fcm",
            &serde_json::json!({
                "app_name": "mail25",
                "token": token,
                "title": notification_title,
                "body": notification_message,
                "data": {
                    "email": email,
                    "ip_addr": ip_addr,
                    "notification_type": notification_type,
                }
            })
        ).await.unwrap_or_else(|err| {
            log::error!("Failed to send login attempt notification: {}", err);
        });
    }
}


pub async fn send_app_2fa_notification(
    rmq_settings: &RmqSettings,
    email: String,
    otp_code: String,
    fcm_tokens: Vec<String>,
) {
    for token in &fcm_tokens {
        // Send notification to RabbitMQ (In background)
        rmq::send_notification_to_rmq(
            rmq_settings,
            "fcm",
            &serde_json::json!({
                "app_name": "mail25",
                "token": token,
                "title": "SSO - Verification Code",
                "body": "Enter this verification code in your page to complete the login process.",
                "data": {
                    "email": email,
                    "otp_code": otp_code,
                    "notification_type": "SSO_2FA_APP_OTP",
                }
            })
        ).await.unwrap_or_else(|err| {
            log::error!("Failed to send app 2FA notification: {}", err);
        });
    }
}


pub async fn send_sms_2fa_notification(
    rmq_settings: &RmqSettings,
    phone_number: String,
    otp_code: String,
) {
    // Send notification to RabbitMQ (In background)
    rmq::send_notification_to_rmq(
        rmq_settings,
        "sms",
        &serde_json::json!({
            "to": phone_number,
            "template": "aio_otp",
            "variables": {
                "to": phone_number,
                "otp": otp_code
            }
        })
    ).await.unwrap_or_else(|err| {
        log::error!("Failed to send SMS 2FA notification: {}", err);
    });
}


pub async fn send_email_2fa_notification(
    rmq_settings: &RmqSettings,
    email: String,
    otp_code: String,
    org_name: String,
    user_name: String,
) {
    // Send notification to RabbitMQ (In background)
    rmq::send_notification_to_rmq(
        rmq_settings,
        "email",
        &serde_json::json!({
            "to": email,
            "template": "otp_verification",
            "variables": {
                "otp": otp_code,
                "organization_name": org_name,
                "name": user_name,
                "year": chrono::Utc::now().year()
            }
        })
    ).await.unwrap_or_else(|err| {
        log::error!("Failed to send Email 2FA notification: {}", err);
    });
}
