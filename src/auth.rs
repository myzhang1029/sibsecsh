use crate::config::Config;
use crate::extend_lettre::new_simple_port;
use crate::ip::get_from_ip;
use ipaddress::IPAddress;
use lettre::smtp::authentication::Credentials;
use lettre::Transport;
use lettre_email::EmailBuilder;
use rand::Rng;
use std::io::{stdin, stdout, Write};
use subprocess::{Exec, Redirection};

/// Trait for authenticate providers
pub trait Authenticator<'auth> {
    /// Initialize authenticator from shell configuration
    fn init(config: &'auth Config) -> Self;
    /// Check if the login is accepted by this authenticator
    /// Some(true) is yes
    /// Some(false) is rejected
    /// None is cancelled
    /// CMD is supplied only when -c cmdline is used and contains the
    /// argument to -c
    fn is_accepted(&self, cmd: Option<String>) -> Option<bool>;
    /// Returns whether this can be used non-interactively
    /// i.e. when -c cmdline is supplied
    fn non_interactive(&self) -> bool {
        false
    }
}

pub struct EmailAuthenticator<'a> {
    config: &'a Config,
    code: u32,
}

impl<'a> EmailAuthenticator<'a> {
    fn gen_code() -> u32 {
        let mut rng = rand::thread_rng();
        let number = rng.gen_range(100000..1000000);
        number
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
            config: config,
            code: code,
        }
    }

    fn is_accepted(&self, _cmd: Option<String>) -> Option<bool> {
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
            if input == shadowed || input == *email {
                tries = 0;
                break;
            }
            info!("Got wrong email {:?}", input);
            eprintln!("Not match");
        }
        if tries != 0 {
            // Maximum number of tries exceeded
            warn!("Maximum number of retries exceeded");
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
        warn!("Maximum number of retries exceeded");
        Some(false)
    }
}

pub struct LocalIPAuthenticator<'a> {
    config: &'a Config,
}

impl<'a> Authenticator<'a> for LocalIPAuthenticator<'a> {
    fn init(config: &'a Config) -> Self {
        LocalIPAuthenticator { config: config }
    }

    fn is_accepted(&self, _cmd: Option<String>) -> Option<bool> {
        let checking = match IPAddress::parse(get_from_ip()) {
            Ok(ok) => ok,
            Err(_e) => return None,
        };
        for network in self.config.accepted_ips.iter() {
            let ipaddress = match IPAddress::parse(network) {
                Ok(ok) => ok,
                Err(errstr) => {
                    warn!("Bad ip address pattern {:?}", errstr);
                    continue;
                }
            };
            if ipaddress.includes(&checking) {
                return Some(true);
            }
        }
        None
    }

    fn non_interactive(&self) -> bool {
        true
    }
}

pub struct BypassAuthenticator {}

impl Authenticator<'_> for BypassAuthenticator {
    fn init(_config: &Config) -> Self {
        BypassAuthenticator {}
    }

    fn is_accepted(&self, _cmd: Option<String>) -> Option<bool> {
        if let Some(mut home_dir) = home::home_dir() {
            home_dir.push("NoSec");
            if home_dir.exists() {
                return Some(true);
            }
        }
        None
    }

    fn non_interactive(&self) -> bool {
        true
    }
}
