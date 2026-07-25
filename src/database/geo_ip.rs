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


use crate::models::user::RestrictionPolicy;
use crate::models::mail_svc::GeoIPInfo;
use cidr::{Ipv4Cidr, Ipv6Cidr};
use std::net::IpAddr;
use deadpool_postgres::{
    PoolError as PgError,
    Pool as PgPool
};


fn ip_in_range_bool(ip_str: &str, range_str: &str) -> bool {
    let ip: IpAddr = match ip_str.parse() {
        Ok(ip) => ip,
        Err(_) => return false,
    };

    if let Ok(v4_range) = range_str.parse::<Ipv4Cidr>() {
        if let IpAddr::V4(v4) = ip {
            return v4_range.contains(&v4);
        } else {
            return false;
        }
    }

    if let Ok(v6_range) = range_str.parse::<Ipv6Cidr>() {
        if let IpAddr::V6(v6) = ip {
            return v6_range.contains(&v6);
        } else {
            return false;
        }
    }

    false // invalid CIDR string
}


/// Check if the Geo-IP location is allowed
pub async fn check_if_geo_ip_is_allowed(db_pool: &PgPool, ip_addr: &str, restriction_policy: &Option<RestrictionPolicy>) -> Result<GeoIPInfo, PgError> {
    // There are 2 possibilities here:
    // 1. The user has a restriction policy
    // 2. The user does not have a restriction policy (i.e., no restrictions)
    let (ip_restriction, geo_restriction) = match restriction_policy {
        Some(policy) => (policy.ip_restriction.clone(), policy.geo_restriction.clone()),
        None => (Some(vec![]), Some(vec![])), // No restrictions
    };

    // Convert the Option<Vec<String>> to Vec<String> for easier handling
    let ip_restriction = ip_restriction.unwrap_or_default();
    let geo_restriction = geo_restriction.unwrap_or_default();

    // Check if the IP is in white listing range (False if no IP restriction is set)
    let ip_in_whitelist = ip_restriction.iter().any(|range| ip_in_range_bool(ip_addr, range));

    // Check Geo-IP Location
    let client = db_pool.get().await?;
    let row = client
        .query_one(
            r#"
            SELECT country_iso_code, country_name
            FROM ip_geo_locations
            WHERE network >>= $1
            "#,
            &[&ip_addr.parse::<IpAddr>().ok()],
        )
        .await?;

    let country_iso_code = row.get::<&str, String>("country_iso_code");
    let country_name = row.get::<&str, String>("country_name");

    // Check if the iso_code is in white listing geo restriction (False if no geo restriction is set)
    let iso_code_in_whitelist = geo_restriction.iter().any(|code| code == &country_iso_code);

    Ok(GeoIPInfo {
        ip_in_whitelist,
        iso_code_in_whitelist,
        is_ip_restricted: !ip_restriction.is_empty(),
        is_geo_restricted: !geo_restriction.is_empty(),
        country: country_name,
        iso_code: country_iso_code,
    })
}
