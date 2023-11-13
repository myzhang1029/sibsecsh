//
//  Copyright (C) 2021 Zhang Maiyun <me@maiyun.me>
//
//  This file is part of sib secure shell.
//
//  Sib secure shell is free software: you can redistribute it and/or modify
//  it under the terms of the GNU Affero General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  Sib secure shell is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU Affero General Public License for more details.
//
//  You should have received a copy of the GNU Affero General Public License
//  along with sib secure shell.  If not, see <https://www.gnu.org/licenses/>.
//

use crate::config::SecRcCfg;
use crate::ip::get_from;
use cidr::IpCidr;
use log::warn;
use std::net::IpAddr;

/// Trait for authenticate providers
pub trait Authenticator<'auth> {
    /// Initialize authenticator from shell configuration
    fn init(config: &'auth SecRcCfg) -> Self;
    /// Check if the login is accepted by this authenticator
    /// Some(true) is yes
    /// Some(false) is rejected
    /// None is cancelled
    /// CMD is supplied only when -c cmdline is used and contains the
    /// argument to -c
    fn is_accepted_login(&self) -> Option<bool>;
    /// Check if the execute request is accepted by this authenticator
    /// The modified (if any) command line is put back into cmd
    /// i.e. when -c cmdline is supplied
    fn is_accepted_exec(&self, cmd: &mut String) -> Option<bool>;
}

pub struct LocalIPAuthenticator<'a> {
    config: &'a SecRcCfg,
}

impl<'a> Authenticator<'a> for LocalIPAuthenticator<'a> {
    fn init(config: &'a SecRcCfg) -> Self {
        LocalIPAuthenticator { config }
    }

    fn is_accepted_login(&self) -> Option<bool> {
        let checking: IpAddr = match get_from().parse() {
            Ok(ok) => ok,
            Err(_e) => return None,
        };
        // Cancel this authenticator if None
        if let Some(accepted_ips) = &self.config.accepted_ips {
            for network in accepted_ips {
                let cidr: IpCidr = match network.parse() {
                    Ok(ok) => ok,
                    Err(errstr) => {
                        warn!("Bad CIDR: {:?}", errstr);
                        continue;
                    }
                };
                if cidr.contains(&checking) {
                    warn!("Local login accepted");
                    return Some(true);
                }
            }
        }
        None
    }

    fn is_accepted_exec(&self, _cmd: &mut String) -> Option<bool> {
        self.is_accepted_login()
    }
}

pub struct BypassAuthenticator {}

impl Authenticator<'_> for BypassAuthenticator {
    fn init(_config: &SecRcCfg) -> Self {
        BypassAuthenticator {}
    }

    fn is_accepted_login(&self) -> Option<bool> {
        if let Some(mut home_dir) = home::home_dir() {
            home_dir.push("NoSec");
            if home_dir.exists() {
                warn!("Sibsecsh turned off");
                return Some(true);
            }
        }
        if let Ok(_value) = std::env::var("SIB_FROM_IP") {
            warn!("Nested login accepted");
            return Some(true);
        }
        None
    }

    fn is_accepted_exec(&self, _cmd: &mut String) -> Option<bool> {
        self.is_accepted_login()
    }
}
