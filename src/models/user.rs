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


use crate::handlers::encryption::encrypt;
use serde::{Deserialize, Serialize};
use tokio_postgres::row::Row;
use uuid::Uuid;



#[derive(Serialize, Deserialize)]
pub struct SessionUser {
    pub session_id: Uuid,

    pub email: String,
    pub domain_name: String,
    pub first_name: String,
    pub last_name: Option<String>,

    pub primary_phone: String,
    pub secondary_email: Option<String>,
    pub encrypted_password: String,

    pub device_details: serde_json::Value,
    pub is_active: bool,

    pub organization_id: Uuid,
    pub organization_name: String,
}


#[derive(Serialize)]
pub struct RestrictionPolicy {
    pub policy_id: Uuid,
    pub policy_name: String,
    pub policy_description: String,
    pub ip_restriction: Option<Vec<String>>,
    pub geo_restriction: Option<Vec<String>>,
}


#[derive(Serialize)]
pub struct UserInfo {
    pub email: String,
    pub domain_name: String,
    pub first_name: String,
    pub last_name: Option<String>,

    pub primary_phone: String,
    pub secondary_email: Option<String>,
    pub password_bcrypt: String,

    pub is_app_2fa_enabled: bool,
    pub is_sms_2fa_enabled: bool,
    pub is_email_2fa_enabled: bool,

    pub organization_id: Uuid,
    pub organization_name: String,

    pub restriction_policy: Option<RestrictionPolicy>,
    pub auth_app_fcm_tokens: Vec<String>,
    pub session_timeout: i32,

    pub is_mail_service_enabled: bool,
    pub is_chat_service_enabled: bool,
    pub is_file_service_enabled: bool,
}


#[derive(Serialize)]
pub struct ChatInfo {
    pub email: String,
    pub domain_name: String,
    pub first_name: String,
    pub last_name: Option<String>,
    pub enable_file_sharing: bool,
    pub organization_id: Uuid,
    pub organization_name: String,
    
    pub file_size_limit_mb: i32,
    pub enable_group_chat: bool,
    pub enable_direct_chat: bool,

    pub quota_allocated: f64,
    pub quota_utilized: f64,
}


#[derive(Serialize)]
pub struct FileInfo {
    pub email: String,
    pub domain_name: String,
    pub first_name: String,
    pub last_name: Option<String>,
    pub organization_id: Uuid,
    pub organization_name: String,

    pub is_file_versioning_enabled: bool,
    pub is_sharing_enabled: bool,

    pub quota_allocated: f64,
    pub quota_utilized: f64,
}


// ------- Implementations ------- //


impl From<Row> for SessionUser {
    fn from(row: Row) -> Self {
        SessionUser {
            session_id: row.get("session_id"),
            is_active: row.get("is_active"),
            email: row.get("email"),
            domain_name: row.get("domain_name"),
            first_name: row.get("first_name"),
            last_name: row.get("last_name"),

            encrypted_password: row.get("encrypted_password"),
            primary_phone: row.get("primary_phone"),
            secondary_email: row.get("secondary_email"),
            device_details: row.get("device_details"),

            organization_id: row.get("organization_id"),
            organization_name: row.get("organization_name"),
        }
    }
}
            

impl SessionUser {
    pub fn create(user_info: &UserInfo, password: &str, device_details: &serde_json::Value, is_active: bool) -> Self {
        let encrypted_password = encrypt(password);
        SessionUser {
            session_id: Uuid::new_v4(),

            email: user_info.email.clone(),
            domain_name: user_info.domain_name.clone(),
            first_name: user_info.first_name.clone(),
            last_name: user_info.last_name.clone(),
            encrypted_password,
            primary_phone: user_info.primary_phone.clone(),
            secondary_email: user_info.secondary_email.clone(),
            device_details: device_details.clone(),
            is_active,

            organization_id: user_info.organization_id,
            organization_name: user_info.organization_name.clone(),
        }
    }


    pub fn self_clone(&self) -> Self {
        SessionUser {
            session_id: self.session_id,
            email: self.email.clone(),
            domain_name: self.domain_name.clone(),
            first_name: self.first_name.clone(),
            last_name: self.last_name.clone(),
            encrypted_password: self.encrypted_password.clone(),
            primary_phone: self.primary_phone.clone(),
            secondary_email: self.secondary_email.clone(),
            device_details: self.device_details.clone(),
            is_active: self.is_active,
            organization_id: self.organization_id,
            organization_name: self.organization_name.clone(),
        }
    }
}


impl From<Row> for UserInfo {
    fn from(row: Row) -> Self {
        let restriction_policy = if let Some(policy_id) = row.get::<&str, Option<Uuid>>("policy_id") {
            Some(RestrictionPolicy {
                policy_id,
                policy_name: row.get("policy_name"),
                policy_description: row.get("policy_description"),
                ip_restriction: row.get("ip_restriction"),
                geo_restriction: row.get("geo_restriction"),
            })
        } else {
            None
        };

        UserInfo {
            email: row.get("email"),
            domain_name: row.get("domain_name"),
            first_name: row.get("first_name"),
            last_name: row.get("last_name"),

            primary_phone: row.get("primary_phone"),
            secondary_email: row.get("secondary_email"),
            password_bcrypt: row.get("password_bcrypt"),

            is_app_2fa_enabled: row.get("is_app_2fa_enabled"),
            is_sms_2fa_enabled: row.get("is_sms_2fa_enabled"),
            is_email_2fa_enabled: row.get("is_email_2fa_enabled"),

            organization_id: row.get("organization_id"),
            organization_name: row.get("organization_name"),

            restriction_policy,
            auth_app_fcm_tokens: row.get("auth_app_fcm_tokens"),
            session_timeout: row.get("session_timeout"),

            is_mail_service_enabled: row.get("is_mail_service_enabled"),
            is_chat_service_enabled: row.get("is_chat_service_enabled"),
            is_file_service_enabled: row.get("is_file_service_enabled"),
        }
    }
}


impl UserInfo {
    /// Validate the provided password against the stored password hash using bcrypt
    pub fn verify_password(&self, password: &str) -> bool {
        bcrypt::verify(password, &self.password_bcrypt).unwrap_or(false)
    }

    /// Get a masked version of the user's secondary email for security reasons
    pub fn masked_secondary_email(&self) -> String {
        let email = match &self.secondary_email {
            Some(email) => email,
            None => return "".to_string(),
        };

        let parts: Vec<&str> = email.split('@').collect();
        if parts.len() == 2 {
            let local_part = parts[0];
            let domain_part = parts[1];
            let masked_local = if local_part.len() > 3 {
                format!("{}***", &local_part[..3])
            } else {
                format!("{}***", local_part)
            };
            format!("{}@{}", masked_local, domain_part)
        } else {
            email.clone()
        }
    }

    /// Get a masked version of the user's primary phone number for security reasons
    pub fn masked_primary_phone(&self) -> String {
        // Give first 3 characters and last 4 characters of phone number, mask the middle part with asterisks
        let phone = &self.primary_phone;

        if phone.len() > 7 {
            let start = &phone[..3];
            let end = &phone[phone.len() - 4..];
            format!("{}****{}", start, end)
        } else {
            // If phone number is too short, just mask the last 4 characters
            let end = if phone.len() > 4 {
                &phone[phone.len() - 4..]
            } else {
                phone
            };
            format!("****{}", end)
        }
    }
}


impl From<Row> for ChatInfo {
    fn from(row: Row) -> Self {
        ChatInfo {
            email: row.get("email"),
            domain_name: row.get("domain_name"),
            first_name: row.get("first_name"),
            last_name: row.get("last_name"),
            enable_file_sharing: row.get("enable_file_sharing"),
            organization_id: row.get("organization_id"),
            organization_name: row.get("organization_name"),
            file_size_limit_mb: row.get("file_size_limit_mb"),
            enable_group_chat: row.get("enable_group_chat"),
            enable_direct_chat: row.get("enable_direct_chat"),
            quota_allocated: row.get("quota_allocated"),
            quota_utilized: row.get("quota_utilized"),
        }
    }
}


impl From<Row> for FileInfo {
    fn from(row: Row) -> Self {
        FileInfo {
            email: row.get("email"),
            domain_name: row.get("domain_name"),
            first_name: row.get("first_name"),
            last_name: row.get("last_name"),
            organization_id: row.get("organization_id"),
            organization_name: row.get("organization_name"),
            quota_allocated: row.get("quota_allocated"),
            quota_utilized: row.get("quota_utilized"),
            is_file_versioning_enabled: row.get("is_file_versioning_enabled"),
            is_sharing_enabled: row.get("is_sharing_enabled"),
        }
    }
}
