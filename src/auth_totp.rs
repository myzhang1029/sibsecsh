use crate::auth::Authenticator;
use crate::config::Config;
use oath::{totp_now, HashType};
use std::io::{stdin, stdout, Write};

pub struct TotpAuthenticator<'a> {
    config: &'a Config,
    hashtype: HashType,
}

impl<'a> TotpAuthenticator<'a> {
    fn compare_code(&self, code: u64) -> Option<bool> {
        // XXX: 90secs
        Some(
            code == totp_now(
                &b64_to_hex(&self.config.totp_secret)?,
                self.config.totp_digits,
                0,
                self.config.totp_timestep,
                &self.hashtype,
            )
            .ok()?,
        )
    }
}

impl<'a> Authenticator<'a> for TotpAuthenticator<'a> {
    fn init(config: &'a Config) -> Self {
        let mut hashtype = HashType::SHA1;
        let strlen = config.totp_hash.len();

        if config.totp_hash[0..3].to_uppercase() != "SHA" {
            error!("Invalid totp_hash type");
        } else if config.totp_hash[strlen - 3..strlen] == *"512" {
            hashtype = HashType::SHA512;
        } else if config.totp_hash[strlen - 3..strlen] == *"256" {
            hashtype = HashType::SHA256;
        }
        TotpAuthenticator {
            config: config,
            hashtype: hashtype,
        }
    }

    fn is_accepted_login(&self) -> Option<bool> {
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
            input = input.trim().to_string();
            if input == "" {
                // Skip this authenticator
                return None;
            }
            if let Ok(input) = input.parse() {
                if self.compare_code(input)? {
                    return Some(true);
                }
            }
            info!("Got wrong code {:?}", input);
            eprintln!("Not match");
        }
        // Maximum number of tries exceeded
        error!("Maximum number of retries exceeded");
        Some(false)
    }

    fn is_accepted_exec(&self, cmd: &mut String) -> Option<bool> {
        // A missing code becomes None
        let input: u64 = cmd[0..(self.config.totp_digits as usize)].parse().ok()?;
        if self.compare_code(input)? {
            // Remove the code
            *cmd = cmd[(self.config.totp_digits as usize)..cmd.len()].to_string();
            Some(true)
        } else {
            None
        }
    }
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
    let mut result = String::with_capacity(b64.len() * 5 / 4 + 1);
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
