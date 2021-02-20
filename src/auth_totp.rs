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
                &self.config.totp_secret,
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

        if config.totp_hash[0..3].to_string().to_uppercase() != "SHA" {
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
            if let Ok(input) = input.parse() {
                if self.compare_code(input)? {
                    tries = 0;
                    break;
                }
            }
            info!("Got wrong code {:?}", input);
            eprintln!("Not match");
        }
        if tries != 0 {
            // Maximum number of tries exceeded
            error!("Maximum number of retries exceeded");
            return Some(false);
        }
        None
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
