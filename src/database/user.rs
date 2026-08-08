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


use crate::models::user::{ChatInfo, FileInfo, SessionUser, UserInfo};
use crate::models::mail_svc::MailServiceSession;
use deadpool_postgres::{
    PoolError as PgError,
    Pool as PgPool
};


// -- SSO (Single Sign-On) Sessions (only for MailBox/E-Mail based users)
// CREATE TABLE sso_sessions (
//     session_id UUID PRIMARY KEY,    -- Cookie based session ID for SSO session
//     email VARCHAR(254) NOT NULL REFERENCES email_identities(email) ON DELETE CASCADE,
//     domain_name VARCHAR(254) NOT NULL REFERENCES domains(domain_name) ON DELETE CASCADE,
//     organization_id UUID NOT NULL REFERENCES organizations(organization_id) ON DELETE CASCADE,

//     encrypted_password TEXT NOT NULL,  -- We need it for IMAP / SMTP calls

//     device_details JSONB NOT NULL,
//     is_active BOOLEAN DEFAULT TRUE NOT NULL,    -- Is the session active

//     -- When the SSO session was created
//     created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
//     -- When the user last authenticated using this SSO session
//     last_auth_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
// );


/// Fetch user by email, only if the user and their organization are active
pub async fn get_user_by_email(db_pool: &PgPool, email: &str) -> Result<Option<UserInfo>, PgError> {
    let client = db_pool.get().await?;

    let row = client
        .query_opt(
            r#"
            SELECT
                eid.email,
                eid.domain_name,
                eid.first_name,
                eid.last_name,

                eid.primary_phone,
                eid.secondary_email,
                eid.password_bcrypt,
                eid.is_app_2fa_enabled,
                eid.is_sms_2fa_enabled,
                eid.is_email_2fa_enabled,

                eid.restriction_policy_id,

                d.session_timeout,

                o.organization_id,
                o.organization_name,

                rp.policy_id,
                rp.policy_name,
                rp.policy_description,
                rp.ip_restriction,
                rp.geo_restriction,
                rp.is_active AS restriction_policy_active,

                -- Fetch FCM tokens for the user's auth app sessions
                COALESCE(
                    (
                        SELECT array_agg(DISTINCT mas.fcm_token)
                        FROM mail25_app_sessions AS mas
                        WHERE mas.email = eid.email
                        AND mas.domain_name = eid.domain_name
                    ),
                    ARRAY[]::TEXT[]
                ) AS auth_app_fcm_tokens,

                -- Check if the user has mail service, chat service, and file service enabled
                EXISTS (
                    SELECT 1
                    FROM mailboxes AS mb
                    WHERE mb.email = eid.email
                    AND mb.is_enabled = TRUE
                ) AS is_mail_service_enabled,

                EXISTS (
                    SELECT 1
                    FROM chat_users AS cu
                    WHERE cu.email = eid.email
                    AND cu.is_enabled = TRUE
                ) AS is_chat_service_enabled,

                EXISTS (
                    SELECT 1
                    FROM file_users AS fu
                    WHERE fu.email = eid.email
                    AND fu.is_enabled = TRUE
                ) AS is_file_service_enabled

            FROM email_identities AS eid

            INNER JOIN domains AS d
                ON d.domain_name = eid.domain_name

            INNER JOIN organizations AS o
                ON o.organization_id = d.managed_by

            LEFT JOIN restriction_policies AS rp
                ON rp.policy_id = eid.restriction_policy_id
                AND rp.is_active = TRUE

            WHERE
                eid.email = $1

                -- Email Identity checks
                AND eid.is_enabled = TRUE
                AND eid.is_password_expired = FALSE

                -- domain checks
                AND d.is_active = TRUE
                AND d.is_dns_txt_verified = TRUE

                -- owning org check
                AND o.is_active = TRUE

                -- parent org checks
                AND NOT EXISTS (
                    SELECT 1
                    FROM organizations parent_org
                    WHERE parent_org.organization_id::text = ANY(o.hierarchy_path)
                    AND parent_org.is_active = FALSE
                )
            "#,
            &[&email],
        )
        .await?;

    Ok(row.map(UserInfo::from))
}


pub async fn create_sso_session(db_pool: &PgPool, user_session: &SessionUser) -> Result<(), PgError> {
    let client = db_pool.get().await?;

    client
        .execute(
            r#"
            INSERT INTO 
                sso_sessions (
                    session_id,
                    email,
                    domain_name,
                    organization_id,
                    encrypted_password,
                    device_details,
                    is_active
                )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
            &[
                &user_session.session_id,
                &user_session.email,
                &user_session.domain_name,
                &user_session.organization_id,
                &user_session.encrypted_password,
                &user_session.device_details,
                &user_session.is_active,
            ],
        )
        .await?;

    Ok(())
}


pub async fn update_sso_session_last_auth(db_pool: &PgPool, session_id: &uuid::Uuid) -> Result<(), PgError> {
    let client = db_pool.get().await?;

    client
        .execute(
            r#"
            UPDATE sso_sessions
            SET last_auth_at = CURRENT_TIMESTAMP
            WHERE session_id = $1
            "#,
            &[&session_id],
        )
        .await?;

    Ok(())
}


pub async fn update_sso_session_active_status(db_pool: &PgPool, session_id: &uuid::Uuid, is_active: bool) -> Result<(), PgError> {
    let client = db_pool.get().await?;

    client
        .execute(
            r#"
            UPDATE sso_sessions
            SET is_active = $2
            WHERE session_id = $1
            "#,
            &[&session_id, &is_active],
        )
        .await?;

    Ok(())
}


pub async fn delete_sso_session(db_pool: &PgPool, session_id: &uuid::Uuid) -> Result<(), PgError> {
    let client = db_pool.get().await?;

    client
        .execute(
            r#"
            DELETE FROM sso_sessions WHERE session_id = $1
            "#,
            &[&session_id],
        )
        .await?;

    Ok(())
}


pub async fn get_sso_session(db_pool: &PgPool, session_id: &uuid::Uuid) -> Result<Option<SessionUser>, PgError> {
    let client = db_pool.get().await?;

    let row = client
        .query_opt(
            r#"
            SELECT
                s.session_id,
                s.is_active,
                s.email,
                s.domain_name,

                eid.first_name,
                eid.last_name,
                eid.primary_phone,
                eid.secondary_email,

                s.encrypted_password,
                s.device_details,

                o.organization_id,
                o.organization_name

            FROM sso_sessions AS s

            INNER JOIN email_identities AS eid
                ON eid.email = s.email

            INNER JOIN domains AS d
                ON d.domain_name = s.domain_name

            INNER JOIN organizations AS o
                ON o.organization_id = s.organization_id

            WHERE
                s.session_id = $1

                AND eid.is_enabled = TRUE
                AND eid.is_password_expired = FALSE

                AND d.is_active = TRUE

                AND o.is_active = TRUE

                AND NOT EXISTS (
                    SELECT 1
                    FROM organizations parent_org
                    WHERE parent_org.organization_id::text = ANY(o.hierarchy_path)
                    AND parent_org.is_active = FALSE
                )
            "#,
            &[session_id],
        )
        .await?;

    Ok(row.map(SessionUser::from))
}


pub async fn get_chat_info_from_user_id(db_pool: &PgPool, user_id: &str) -> Result<Option<ChatInfo>, PgError> {
    let client = db_pool.get().await?;

    let row = client
        .query_opt(
            r#"
            SELECT
                eid.email,
                eid.domain_name,
                eid.first_name,
                eid.last_name,

                cs.enable_file_sharing,
                cs.file_size_limit_mb,
                cs.enable_group_chat,
                cs.enable_direct_chat,
                cs.quota_allocated::DOUBLE PRECISION,
                cs.quota_utilized::DOUBLE PRECISION,

                o.organization_id,
                o.organization_name

            FROM chat_users AS cu

            INNER JOIN email_identities AS eid
                ON eid.email = cu.email

            INNER JOIN domains AS d
                ON d.domain_name = eid.domain_name

            INNER JOIN organizations AS o
                ON o.organization_id = d.managed_by

            INNER JOIN chat_settings AS cs
                ON cs.organization_id = o.organization_id

            WHERE
                cu.email = $1

                AND cu.is_enabled = TRUE

                AND eid.is_enabled = TRUE
                AND eid.is_password_expired = FALSE

                AND d.is_active = TRUE

                AND o.is_active = TRUE
                AND o.chat_service_enabled = TRUE

                AND NOT EXISTS (
                    SELECT 1
                    FROM organizations parent_org
                    WHERE parent_org.organization_id::text = ANY(o.hierarchy_path)
                      AND parent_org.is_active = FALSE
                )
            "#,
            &[&user_id],
        )
        .await?;

    Ok(row.map(ChatInfo::from))
}


pub async fn update_chat_service_last_active_at(db_pool: &PgPool, user_email: &str) -> Result<(), PgError> {
    let client = db_pool.get().await?;

    client
        .execute(
            r#"
            UPDATE chat_users
            SET last_active_at = NOW()
            WHERE email = $1
            "#,
            &[&user_email],
        )
        .await?;

    Ok(())
}


pub async fn get_mail_service_session(db_pool: &PgPool, email: &str, ip_addr: &str, domain: &str) -> Result<Option<MailServiceSession>, PgError> {
    let client = db_pool.get().await?;

    let row = client
        .query_opt(
            r#"
            SELECT
                ms.attempted_by,
                ms.origin_ip,
                ms.domain_name,
                ms.is_active
            FROM mailbox_sessions ms
            JOIN mailboxes mb
                ON mb.email = ms.attempted_by
            JOIN email_identities ei
                ON ei.email = mb.email
            JOIN domains d
                ON d.domain_name = mb.domain_name
            JOIN organizations org
                ON org.organization_id = d.managed_by
            WHERE
                ms.attempted_by = $1
                AND ms.origin_ip = $2
                AND ms.domain_name = $3
                AND d.is_active
                AND d.is_dns_txt_verified
                AND ei.is_enabled
                AND mb.is_enabled
                AND org.is_active
                AND org.email_service_enabled
            "#,
            &[&email, &ip_addr, &domain],
        )
        .await?;

    Ok(row.map(MailServiceSession::from))
}


pub async fn create_mail_service_session(
    db_pool: &PgPool,
    session_info: &MailServiceSession,
    session_timeout: i32,
) -> Result<(), PgError> {
    let client = db_pool.get().await?;
    let geo_ip_info = session_info.geo_ip_info.as_ref().unwrap();
    let geo_ip_info = serde_json::to_string(geo_ip_info).unwrap_or_else(|_| "{}".to_string());
    log::debug!("Creating mail service session for email: {}, ip: {}, domain: {}, geo_ip_info: {}, is_active: {}, session_timeout: {} minutes", session_info.email, session_info.ip_addr, session_info.domain, geo_ip_info, session_info.is_active, session_timeout);

    client
    // INSERT INTO mailbox_sessions (
    //     origin_ip,
    //     attempted_by,
    //     domain_name,
    //     geo_ip_location,
    //     is_active,
    //     session_expires_at
    // )
    // VALUES (
    //     $1,
    //     $2,
    //     $3,
    //     ($4::TEXT)::JSONB,
    //     $5,
    //     CURRENT_TIMESTAMP + ($6 * INTERVAL '1 minute')
    // )
    // ON CONFLICT (origin_ip, attempted_by)
    // DO UPDATE
    // SET
    //     geo_ip_location = EXCLUDED.geo_ip_location,
    //     is_active = EXCLUDED.is_active,
    //     session_expires_at = EXCLUDED.session_expires_at
        .execute(
            r#"
            INSERT INTO mailbox_sessions (origin_ip, attempted_by,
            domain_name, geo_ip_location, is_active, session_expires_at)
            VALUES ($1, $2, $3, ($4::text)::jsonb, $5, CURRENT_TIMESTAMP + ($6 || ' minutes')::interval)
             ON CONFLICT (origin_ip, attempted_by) DO UPDATE
             SET geo_ip_location = EXCLUDED.geo_ip_location,
                 is_active = EXCLUDED.is_active,
                 session_expires_at = EXCLUDED.session_expires_at
            "#,
            &[
                &session_info.ip_addr,
                &session_info.email,
                &session_info.domain,
                &geo_ip_info,
                &session_info.is_active,
                &session_timeout.to_string(),
            ]
        )
        .await?;

    Ok(())
}


pub async fn get_file_info_from_user_id(
    db_pool: &PgPool,
    user_email: &str,
) -> Result<Option<FileInfo>, PgError> {
    let client = db_pool.get().await?;

    let row = client
        .query_opt(
            r#"
            SELECT
                eid.email,
                eid.domain_name,
                eid.first_name,
                eid.last_name,

                o.organization_id,
                o.organization_name,

                fs.is_file_versioning_enabled,
                fs.is_sharing_enabled,

                fu.quota_allocated::DOUBLE PRECISION,
                fu.quota_utilized::DOUBLE PRECISION

            FROM email_identities AS eid

            INNER JOIN domains AS d
                ON d.domain_name = eid.domain_name

            INNER JOIN organizations AS o
                ON o.organization_id = d.managed_by

            INNER JOIN file_settings AS fs
                ON fs.organization_id = o.organization_id

            INNER JOIN file_users AS fu
                ON fu.email = eid.email

            LEFT JOIN restriction_policies AS rp
                ON rp.policy_id = eid.restriction_policy_id
                AND rp.is_active = TRUE

            WHERE
                eid.email = $1

                -- Email Identity checks
                AND eid.is_enabled = TRUE
                AND eid.is_password_expired = FALSE

                -- Domain checks
                AND d.is_active = TRUE
                AND d.is_dns_txt_verified = TRUE

                -- Organization checks
                AND o.is_active = TRUE

                -- File service checks
                AND fu.is_enabled = TRUE

                -- Parent organization checks
                AND NOT EXISTS (
                    SELECT 1
                    FROM organizations parent_org
                    WHERE parent_org.organization_id::text = ANY(o.hierarchy_path)
                      AND parent_org.is_active = FALSE
                )
            "#,
            &[&user_email],
        )
        .await?;

    Ok(row.map(FileInfo::from))
}


pub async fn update_file_service_last_active_at(db_pool: &PgPool, user_email: &str) -> Result<(), PgError> {
    let client = db_pool.get().await?;

    client
        .execute(
            r#"
            UPDATE file_users
            SET last_active_at = NOW()
            WHERE email = $1
            "#,
            &[&user_email],
        )
        .await?;

    Ok(())
}
