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

use crate::auth::Authenticator;
use crate::config::SecRcCfg;
use log::{error, warn};
use std::io::{stdin, stdout, Write};
use totp_rs::{Algorithm, Secret, TOTP};

pub struct TotpAuthenticator<'a> {
    config: &'a SecRcCfg,
    enabled: bool,
    hashtype: Algorithm,
}

impl<'a> TotpAuthenticator<'a> {
    /// Compares a TOTP code with the correct one, tolerating the one before
    /// and the one after to take networking and time inaccuracy into account.
    fn compare_code(&self, code: &str) -> Option<bool> {
        let Ok(secret) = Secret::Encoded(
            self.config
                .totp_secret
                .clone()
                .expect("Bug: `config.totp_secret` should not be `None` here"),
        )
        .to_bytes() else {
            error!("Invalid TOTP secret");
            return None;
        };
        let totp = TOTP {
            algorithm: self.hashtype,
            digits: self
                .config
                .totp_digits
                .expect("Bug: `config.totp_digit` should not be `None` here")
                as usize,
            skew: 1,
            step: self
                .config
                .totp_timestep
                .expect("Bug: `config.totp_timestep` should not be `None` here"),
            secret,
        };
        totp.check_current(code)
            .map_err(|e| error!("Cannot retrieve system time: {e}"))
            .ok()
    }
}

impl<'a> Authenticator<'a> for TotpAuthenticator<'a> {
    fn init(config: &'a SecRcCfg) -> Self {
        let mut hashtype = Algorithm::SHA1;
        if let Some(config_hash_type) = &config.totp_hash {
            let strlen = config_hash_type.len();

            if config_hash_type[0..3].to_uppercase() != "SHA" {
                error!("Invalid totp_hash type");
            } else if config_hash_type[strlen - 3..strlen] == *"512" {
                hashtype = Algorithm::SHA512;
            } else if config_hash_type[strlen - 3..strlen] == *"256" {
                hashtype = Algorithm::SHA256;
            }
        }
        let enabled = config.totp_secret.is_some();
        TotpAuthenticator {
            config,
            enabled,
            hashtype,
        }
    }

    fn is_accepted_login(&self) -> Option<bool> {
        if self.enabled {
            let stdin = stdin();
            let mut tries: u8 = 0;
            while tries < 3 {
                let mut input = String::new();
                tries += 1;
                print!("Enter the code displayed on your device: ");
                stdout().flush().ok();
                if let Err(error) = stdin.read_line(&mut input) {
                    error!("{}", error);
                    return None;
                }
                let input = input.trim();
                if input.is_empty() {
                    // Skip this authenticator
                    return None;
                }
                if self.compare_code(input)? {
                    return Some(true);
                }
                warn!("Wrong code {:?}", input);
            }
            // Maximum number of tries exceeded
            error!("Maximum number of retries exceeded");
            Some(false)
        } else {
            None
        }
    }

    fn is_accepted_exec(&self, cmd: &mut String) -> Option<bool> {
        if self.enabled {
            let totp_digits = self
                .config
                .totp_digits
                .expect("Bug: `config.totp_digit` should not be `None` here")
                as usize;
            if cmd.len() < totp_digits {
                return None;
            }
            // A missing code becomes None
            let input = &cmd[0..totp_digits];
            if self.compare_code(input)? {
                // Remove the code
                *cmd = cmd[totp_digits..cmd.len()].to_string();
                Some(true)
            } else {
                None
            }
        } else {
            None
        }
    }
}

/* Not used anymore, kept for reference.
fn b64_to_bytes(b64: &str) -> Option<Vec<u8>> {
    let no_equal = b64.trim_end_matches('=').to_uppercase();
    let num_padded_zero: u8 = match b64.len() - no_equal.len() {
        0 => 0, // not padded
        1 => 3, // = indicates three padded zeroes
        3 => 1, // === indicates one padded zero
        4 => 4, // ==== indicates four padded zeroes
        6 => 2, // ====== indicates two padded zeroes
        _ => {
            error!("Invalid base32 padding");
            return None;
        }
    };
    let mut result: Vec<u8> = Vec::with_capacity(b64.len() * 5 / 8);
    let mut buf_cur: u16 = 0;
    let mut bits_have: u8 = 0;
    for (i, ch) in no_equal.chars().enumerate() {
        let value_ch = if ch.is_ascii_alphabetic() {
            (ch as u8) - b'A' // 'A' becomes 0
        } else if ch.is_digit(8) && ch != '0' && ch != '1' {
            (ch as u8) - b'2' + 26 // '2' becomes 26
        } else {
            return None;
        };
        buf_cur = (buf_cur << 5) + u16::from(value_ch);
        bits_have += 5;
        if i == no_equal.len() - 1 {
            // Remove padded zeroes
            buf_cur >>= num_padded_zero;
            bits_have -= num_padded_zero;
        }
        while bits_have >= 8 {
            bits_have -= 8;
            // Discarding the bits on the right, keeping 8 bits. Use u16
            // to be type-consistent
            let value: u16 = buf_cur >> bits_have;
            buf_cur -= value << bits_have; // Remove processed bits
            #[allow(clippy::cast_possible_truncation)]
            result.push(value as u8); // No overflow should occur
        }
    }
    Some(result)
}

fn b64_to_hex(b64: &str) -> Option<String> {
    //const conversion: &'static str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    const HEX_TABLE: &'static str = "0123456789ABCDEF";
    let no_equal = b64.trim_end_matches('=').to_uppercase();
    let num_padded_zero: u8 = match b64.len() - no_equal.len() {
        0 => 0, // not padded
        1 => 3, // = indicates three padded zeroes
        3 => 1, // === indicates one padded zero
        4 => 4, // ==== indicates four padded zeroes
        6 => 2, // ====== indicates two padded zeroes
        _ => {
            error!("Invalid base32 padding");
            return None;
        }
    };
    let mut result = String::with_capacity(b64.len() * 5 / 4);
    let mut buf_cur: u8 = 0;
    let mut bits_have: u8 = 0;
    for (i, ch) in no_equal.chars().enumerate() {
        let value_ch = if ch.is_ascii_alphabetic() {
            (ch as u8) - ('A' as u8) // 'A' becomes 0
        } else if ch.is_digit(8) && ch != '0' && ch != '1' {
            (ch as u8) - ('2' as u8) + 26 // '2' becomes 26
        } else {
            return None;
        };
        buf_cur = (buf_cur << 5) + value_ch;
        bits_have += 5;
        if i == no_equal.len() - 1 {
            // Remove padded zeroes
            buf_cur >>= num_padded_zero;
            bits_have -= num_padded_zero;
        }
        while bits_have >= 4 {
            bits_have -= 4;
            let value: u8 = buf_cur >> bits_have; // Discarding the bits on the right, keeping 4 bits
            buf_cur -= value << bits_have; // Remove processed bits
            result.push(HEX_TABLE.chars().nth(value as usize).unwrap()); // No overflow should occur
        }
    }
    Some(result)
}
*/
