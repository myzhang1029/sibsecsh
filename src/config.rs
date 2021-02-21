use crate::ip::get_from_ip;
use exec::Command;
use serde::Deserialize;
use std::env;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::prelude::*;
use std::io::{Error, ErrorKind};

/// Type for deserializing a secrc.toml
#[derive(Deserialize, Debug)]
struct SecRc {
    accepted_ips: Option<Vec<String>>,
    email: Option<String>,
    shell: Option<String>,
    shell_args: Option<String>,
    log_file: Option<String>,
    tmpdir: Option<String>,
    mail_host: Option<String>,
    mail_port: Option<u16>,
    mail_from: Option<String>,
    mail_passwdcmd: Option<String>,
    totp_secret: Option<String>,
    totp_digits: Option<u32>,
    totp_timestep: Option<u64>,
    totp_hash: Option<String>,
}

/// Representing a sib secure shell configuration
/// Authenticator parameters are public
#[derive(Debug)]
pub struct Config {
    pub accepted_ips: Vec<String>,
    pub email: String,
    shell: String,
    shell_args: String,
    log_file: String,
    pub tmpdir: String,
    pub mail_host: String,
    pub mail_port: u16,
    pub mail_from: String,
    pub mail_passwdcmd: String,
    pub totp_secret: String,
    pub totp_digits: u32,
    pub totp_timestep: u64,
    pub totp_hash: String,
}

impl Config {
    /// Parse a configuration file in TOML format ar FILE_PATH
    pub fn parse_config(&mut self, file_path: &str) -> io::Result<()> {
        let mut file = File::open(file_path)?;
        let mut file_content = String::new();
        file.read_to_string(&mut file_content)?;
        let toml_content: SecRc = toml::from_str(&file_content)?;
        if let Some(accepted_ips) = toml_content.accepted_ips {
            self.accepted_ips = accepted_ips;
        }
        if let Some(email) = toml_content.email {
            self.email = email;
        }
        if let Some(shell) = toml_content.shell {
            self.shell = shell;
        }
        if let Some(shell_args) = toml_content.shell_args {
            self.shell_args = shell_args;
        }
        if let Some(log_file) = toml_content.log_file {
            self.log_file = log_file;
        }
        if let Some(tmpdir) = toml_content.tmpdir {
            self.tmpdir = tmpdir;
        }
        if let Some(mail_host) = toml_content.mail_host {
            self.mail_host = mail_host;
        }
        if let Some(mail_port) = toml_content.mail_port {
            self.mail_port = mail_port;
        }
        if let Some(mail_from) = toml_content.mail_from {
            self.mail_from = mail_from;
        }
        if let Some(mail_passwdcmd) = toml_content.mail_passwdcmd {
            self.mail_passwdcmd = mail_passwdcmd;
        }
        if let Some(totp_secret) = toml_content.totp_secret {
            self.totp_secret = totp_secret;
        }
        if let Some(totp_digits) = toml_content.totp_digits {
            self.totp_digits = totp_digits;
        }
        if let Some(totp_timestep) = toml_content.totp_timestep {
            self.totp_timestep = totp_timestep;
        }
        if let Some(totp_hash) = toml_content.totp_hash {
            self.totp_hash = totp_hash;
        }
        Ok(())
    }

    /// Load configuration from all designated locations, latter overriding the former
    pub fn load_all_possible(&mut self) -> io::Result<()> {
        // A warning will be emitted if no configuration is found
        let mut found_any = false;

        for filename in ["/etc/secrc", "/etc/secrc.toml"].iter() {
            if let Ok(_) = self.parse_config(&filename) {
                found_any = true;
            }
        }
        if let Some(mut home_dir) = home::home_dir() {
            home_dir.push(".secrc");
            if let Some(path_str) = home_dir.to_str() {
                if let Ok(_) = self.parse_config(&path_str) {
                    found_any = true;
                }
            }
            home_dir.set_extension("toml");
            if let Some(path_str) = home_dir.to_str() {
                if let Ok(_) = self.parse_config(&path_str) {
                    found_any = true;
                }
            }
        }
        if found_any {
            Ok(())
        } else {
            Err(Error::new(ErrorKind::Other, "No configuration found"))
        }
    }

    /// Open the log file specified in the config in append mode
    pub fn open_log(&self) -> io::Result<File> {
        let mut logfile_open_options = OpenOptions::new();
        logfile_open_options
            .create(true)
            .append(true)
            .open(&self.log_file)
    }

    /// Execute the configured shell, replacing the current process
    pub fn execute_shell(&self, mut additional_params: Vec<String>) -> Result<(), String> {
        let mut args: Vec<String> = self
            .shell_args
            .split_whitespace()
            .map(|x| x.to_string())
            .collect();
        args.append(&mut additional_params);
        env::set_var("SIB_FROM_IP", get_from_ip());

        match search_shells(&self.shell) {
            Ok(found) => {
                if !found {
                    return Err("non-standard shell".to_string());
                }
            }
            Err(e) => {
                warn!("Cannot search for shells: {:?}", e);
            }
        };
        Err(format!(
            "Cannot execute shell{:?}",
            Command::new(self.shell.clone()).args(&args).exec()
        ))
    }
}

impl Default for Config {
    fn default() -> Self {
        // This is a fallback since it may not be safe, other users can read it
        // The best practice is to set it in the configuration
        let mut tmpdir = String::from("/tmp/sibsecsh");
        if let Some(mut home_dir) = home::home_dir() {
            home_dir.push(".cache/sibsecsh");
            if let Some(path_string) = home_dir.to_str() {
                tmpdir = path_string.to_string();
            }
        }

        Config {
            accepted_ips: vec![String::from("192.168.1.0/24")],
            email: String::from("target@example.com"),
            shell: String::from("/bin/zsh"),
            shell_args: String::from("--login"),
            log_file: String::from("/var/log/sibsecsh.log"),
            tmpdir: tmpdir,
            mail_host: String::from("smtp.example.com"),
            mail_port: 587,
            mail_from: String::from("from@example.com"),
            mail_passwdcmd: String::from("echo 123456"),
            totp_secret: String::from("-"), // Non-base32 string disables this authenticator
            totp_digits: 6,
            totp_timestep: 30,
            totp_hash: String::from("SHA1"),
        }
    }
}

fn search_shells(shell_name: &str) -> io::Result<bool> {
    const SHELLS_FILE: &'static str = "/etc/shells";
    let mut shells_content = String::new();
    let mut found = false;
    File::open(SHELLS_FILE)?.read_to_string(&mut shells_content)?;
    for shell in shells_content.split_whitespace() {
        if shell == shell_name {
            found = true;
        }
    }
    Ok(found)
}
