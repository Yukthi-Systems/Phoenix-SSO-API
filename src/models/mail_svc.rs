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


use serde::{Deserialize, Serialize};
use tokio_postgres::row::Row;


#[derive(Deserialize, Serialize)]
pub struct GeoIPInfo {
    pub ip_in_whitelist: bool,
    pub iso_code_in_whitelist: bool,

    pub is_ip_restricted: bool,
    pub is_geo_restricted: bool,

    pub country: String,
    pub iso_code: String,
}


#[derive(Serialize, Deserialize)]
pub struct MailServiceSession {
    pub email: String,
    pub ip_addr: String,
    pub domain: String,
    pub geo_ip_info: Option<GeoIPInfo>,
    pub is_active: bool,
}


// ------- Implementations ------- //


impl From<Row> for MailServiceSession {
    fn from(row: Row) -> Self {
        MailServiceSession {
            email: row.get("attempted_by"),
            ip_addr: row.get("origin_ip"),
            domain: row.get("domain_name"),
            geo_ip_info: None, // Why bother fetching geo_ip_info from DB? We don't need it for anything
            is_active: row.get("is_active"),
        }
    }
}


impl GeoIPInfo {
    pub fn validate_geo_ip(&self) -> (bool, String) {
        // There are multiple scenarios here:
        // - If the Geo is restricted and iso_code is not in whitelist, return false
        // - If the Geo is not restricted, then we don't care about the iso_code, return true
        // - If the IP is restricted and ip_addr is not in whitelist, return false
        // - If the IP is not restricted, then we don't care about the ip_addr, return true
        if self.is_geo_restricted && !self.iso_code_in_whitelist {
            return (false, format!("Geo location {} is not allowed", self.country));
        }

        if self.is_ip_restricted && !self.ip_in_whitelist {
            return (false, "IP address is not allowed".to_string());
        }

        (true, "Geo and IP are allowed".to_string())
    }
}


impl MailServiceSession {
    pub fn new(email: String, ip_addr: String, domain: String, geo_ip_info: Option<GeoIPInfo>, is_active: bool) -> Self {
        MailServiceSession {
            email,
            ip_addr,
            domain,
            geo_ip_info,
            is_active,
        }
    }
}
