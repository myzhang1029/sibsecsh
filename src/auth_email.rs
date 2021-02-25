//
//  Copyright (C) 2021 Zhang Maiyun <myzhang1029@hotmail.com>
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
use crate::config::Config;
use crate::extend_lettre::new_simple_port;
use lettre::smtp::authentication::Credentials;
use lettre::Transport;
use lettre_email::EmailBuilder;
use rand::Rng;
use std::fs::{remove_file, File};
use std::io::{stdin, stdout, Read, Write};
use std::path::PathBuf;
use subprocess::{Exec, Redirection};

pub struct EmailAuthenticator<'a> {
    config: &'a Config,
    code: u32,
}

impl<'a> EmailAuthenticator<'a> {
    fn gen_code() -> u32 {
        let mut rng = rand::thread_rng();
        rng.gen_range(100000..1000000)
    }

    fn read_password(&self) -> Result<String, String> {
        let mut args = self.config.mail_passwdcmd.split_whitespace();
        let cmd = args.next().ok_or("Invalid mail_passwdcmd")?;
        let cmd_args: Vec<String> = args.map(|arg| arg.to_string()).collect();

        Ok(Exec::cmd(cmd)
            .args(&cmd_args)
            .stdout(Redirection::Pipe)
            .capture()
            .map_err(|e| format!("Cannot run mail_passwdcmd: {:?}", e))?
            .stdout_str()
            .trim()
            .to_string())
    }

    fn send_email(&self, moreinfo: &str) -> Result<(), String> {
        let email = match EmailBuilder::new()
            .to(self.config.email.clone())
            .from((&self.config.mail_from, "SIB Secure Shell"))
            .subject("Login Code")
            .text(format!("Your code is {}{}.", self.code, moreinfo))
            .build()
        {
            Ok(email) => email,
            Err(error) => return Err(format!("Cannot build email: {:?}", error)),
        };

        let password = self.read_password()?;
        let cred = Credentials::new(self.config.mail_from.clone(), password);

        info!("Sending email to {:?}", self.config.email);

        let mut mailer = new_simple_port(&self.config.mail_host, self.config.mail_port)
            .unwrap()
            .credentials(cred)
            .transport();

        // Send the email
        match mailer.send(email.into()) {
            Ok(_) => {
                debug!("Email sent");
                Ok(())
            }
            Err(e) => Err(format!("Cannot send email: {:?}", e)),
        }
    }
}

impl<'a> Authenticator<'a> for EmailAuthenticator<'a> {
    fn init(config: &'a Config) -> Self {
        let code = EmailAuthenticator::gen_code();
        EmailAuthenticator {
            config,
            code,
        }
    }

    fn is_accepted_login(&self) -> Option<bool> {
        // Make a shadowed email
        let email = &self.config.email;
        let namelen = email.rfind('@')?;
        let shadowed = email[namelen / 2..namelen].to_string();
        let mut shadowemail = email[0..namelen / 2].to_string();
        shadowemail.push_str(&"*".repeat(namelen - namelen / 2));
        shadowemail.push_str(&email[namelen..email.len()]);
        let mut tries: u8 = 0;

        // First ask the user for email
        let stdin = stdin();
        while tries < 3 {
            let mut input = String::new();
            tries += 1;
            print!("Enter your email matching {}: ", shadowemail);
            stdout().flush().ok();
            if let Err(error) = stdin.read_line(&mut input) {
                error!("{}", error);
                return None;
            }
            input = input.trim_end().to_string();
            if input.is_empty() {
                // Skip this authenticator
                return None;
            }
            if input == shadowed || input == *email {
                tries = 0;
                break;
            }
            info!("Got wrong email {:?}", input);
            eprintln!("Not match");
        }
        if tries != 0 {
            // Maximum number of tries exceeded
            error!("Maximum number of retries exceeded");
            return Some(false);
        }
        if let Err(error) = self.send_email("") {
            error!("{}", error);
            return None;
        }
        while tries < 3 {
            let mut input = String::new();
            tries += 1;
            print!("Enter the code sent to your email address, 0 to resend: ");
            stdout().flush().ok();
            if let Err(error) = stdin.read_line(&mut input) {
                error!("{}", error);
                return None;
            }
            let input = input.trim_end().parse();
            if input == Ok(0) {
                // Not counting this one
                tries -= 1;
                if let Err(error) = self.send_email("") {
                    error!("{}", error);
                    return None;
                }
            } else if Ok(self.code) == input {
                println!("Logged in!");
                return Some(true);
            } else {
                // Not 0 nor matched
                info!("Got wrong login code {:?}", input);
                eprintln!("Not match");
            }
        }
        // Maximum number of tries exceeded
        error!("Maximum number of retries exceeded");
        Some(false)
    }

    fn is_accepted_exec(&self, cmd: &mut String) -> Option<bool> {
        let mut sib_code_file = PathBuf::from(&self.config.tmpdir);
        sib_code_file.push("sib_code");
        if *cmd == self.config.email {
            // Send auth code
            if let Err(error) = self.send_email("") {
                error!("{}", error);
            }
            // Write the generated code
            match File::create(sib_code_file) {
                Ok(mut file) => {
                    file.write(&self.code.to_string().as_bytes()).ok();
                }
                // This is certainlty unwanted
                Err(e) => error!("Create code file failed: {}", e),
            }
            // Cancel execution
            return Some(false);
        }
        match File::open(&sib_code_file) {
            Ok(mut file) => {
                let mut code = String::new();
                file.read_to_string(&mut code).ok()?;
                code = code.trim().to_string();
                // If cmd is shorter that 6 chars it's always bad
                if cmd.len() >= 6 && cmd[0..6] == code {
                    // Remove the code from cmd
                    *cmd = cmd[6..cmd.len()].to_string();
                    remove_file(&sib_code_file).ok();
                    Some(true)
                } else {
                    warn!("Read {:?} from code file, found {:?}", code, &cmd[0..6]);
                    None
                }
            }
            Err(e) => {
                // It's probably just chaining to the next authenticator
                info!("Cannot open code file: {}", e);
                None
            }
        }
    }
}
