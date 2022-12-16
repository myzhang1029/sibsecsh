//
//  Copyright (C) 2022 Zhang Maiyun <me@myzhangll.xyz>
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

use crate::auth::Authenticator;
use crate::config::SecRcCfg;
use log::error;
use rand::{distributions::Alphanumeric, Rng};
use std::collections::BTreeMap;
use std::io::{stdin, stdout, Write};

pub struct YubicoAuthenticator {
    // Also serves as `enabled`
    yubico_id: Option<String>,
}

const YUBICO_SERVER: &str = "https://api.yubico.com/wsapi/2.0/verify";

fn verify_otp(otp: &str) -> Result<bool, String> {
    let mut rng = rand::thread_rng();
    // Numeric id
    let id: i32 = rng.gen_range(0..1_000);
    // Random nonce
    let nonce_len = rng.gen_range(16..41);
    let nonce: String = rng
        .sample_iter(&Alphanumeric)
        .take(nonce_len)
        .map(char::from)
        .collect();
    let mut last_error = String::new();
    for _ in 0..3 {
        // TODO: signing
        let resp = ureq::get(YUBICO_SERVER)
            .query("id", &id.to_string())
            .query("nonce", &nonce)
            .query("otp", otp)
            .call();
        if let Ok(resp) = resp {
            // Successful response. Let's verify
            let result = resp.into_string().map_err(|e| e.to_string())?;
            let mut kvs: BTreeMap<String, String> = BTreeMap::new();
            for line in result.split("\r\n") {
                if line.is_empty() {
                    continue;
                }
                let (key, value) = line
                    .split_once('=')
                    .ok_or_else(|| format!("Malformed reply {line:?}: missing key or value"))?;
                kvs.insert(key.to_string(), value.to_string());
            }
            if let Some(returned_otp) = kvs.get("otp") {
                if returned_otp != otp {
                    error!("OTP in the response does not match the request");
                    // Reject
                    return Ok(false);
                }
            } else {
                return Err(String::from("`otp` not in the response"));
            }
            if let Some(returned_nonce) = kvs.get("nonce") {
                if *returned_nonce != nonce {
                    error!("Nonce in the response does not match the request");
                    // Reject
                    return Ok(false);
                }
            } else {
                return Err(String::from("`nonce` not in the response"));
            }
            // TODO: verify signature
            return if let Some(status) = kvs.get("status") {
                if status == "OK" {
                    Ok(true)
                } else {
                    error!("Status {} is not OK", status);
                    // Reject
                    Ok(false)
                }
            } else {
                Err(String::from("`status` not in the response"))
            };
        }
        last_error = resp.unwrap_err().to_string();
    }
    Err(last_error)
}

impl<'a> Authenticator<'a> for YubicoAuthenticator {
    fn init(config: &SecRcCfg) -> Self {
        YubicoAuthenticator {
            yubico_id: if let Some(supplied_yubico_id) = &config.yubico_id {
                if supplied_yubico_id.len() < 12 {
                    None
                } else {
                    Some(supplied_yubico_id[0..12].to_string())
                }
            } else {
                None
            },
        }
    }

    fn is_accepted_login(&self) -> Option<bool> {
        if let Some(yubico_id) = &self.yubico_id {
            print!("Enter your YubiOTP: ");
            let mut input = String::new();
            stdout().flush().ok();
            if let Err(error) = stdin().read_line(&mut input) {
                error!("{}", error);
                return None;
            }
            input = input.trim().to_string();
            if input.is_empty() {
                // Skip this authenticator
                None
            } else if input.len() < 14 {
                error!("Malformed OTP");
                Some(false)
            } else if input[0..12] != *yubico_id {
                error!("Incorrect Yubikey ID");
                Some(false)
            } else {
                verify_otp(&input).map_or_else(
                    |err| {
                        error!("{:?}", err);
                        None
                    },
                    Some,
                )
            }
        } else {
            None
        }
    }

    fn is_accepted_exec(&self, cmd: &mut String) -> Option<bool> {
        if cmd.len() < 44 {
            return None;
        }
        verify_otp(&cmd[0..44]).map_or_else(
            |err| {
                error!("{:?}", err);
                None
            },
            |result| {
                if result {
                    // Remove the code
                    *cmd = cmd[44..cmd.len()].to_string();
                }
                Some(result)
            },
        )
    }
}
