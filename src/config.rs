use serde::Deserialize;
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
}

/// Representing a sib secure shell configuration
#[derive(Debug)]
pub struct Config {
    accepted_ips: Vec<String>,
    email: String,
    shell: String,
    shell_args: String,
    log_file: String,
    tmpdir: String,
    mail_host: String,
    mail_port: u16,
    mail_from: String,
    mail_passwdcmd: String,
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

    pub fn open_log(&self) -> io::Result<File> {
        let mut logfile_open_options = OpenOptions::new();
        logfile_open_options
            .create(true)
            .append(true)
            .open(&self.log_file)
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
        }
    }
}