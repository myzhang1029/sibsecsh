//
//  Copyright (C) 2021 Zhang Maiyun <me@myzhangll.xyz>
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

use crate::ip::get_from;
use exec::Command;
use log::warn;
use serde::Deserialize;
use std::env;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::prelude::*;
use std::io::{Error, ErrorKind};

/// Type for deserializing a secrc.toml
/// Representing a sib secure shell configuration
/// Authenticator parameters are public
#[derive(Deserialize, Debug)]
pub struct SecRcCfg {
    pub accepted_ips: Option<Vec<String>>,
    pub email: Option<String>,
    shell: Option<String>,
    shell_args: Option<String>,
    log_file: Option<String>,
    pub tmpdir: Option<String>,
    pub mail_host: Option<String>,
    pub mail_port: Option<u16>,
    pub mail_from: Option<String>,
    pub mail_passwdcmd: Option<String>,
    pub totp_secret: Option<String>,
    pub totp_digits: Option<u32>,
    pub totp_timestep: Option<u64>,
    pub totp_hash: Option<String>,
}

impl SecRcCfg {
    /// Parse and load a configuration file in TOML format at `FILE_PATH`
    pub fn load_config(&mut self, file_path: &str) -> io::Result<()> {
        let mut file = File::open(file_path)?;
        let mut file_content = String::new();
        file.read_to_string(&mut file_content)?;
        let mut toml_content: SecRcCfg = toml::from_str(&file_content)?;
        // Override the current value if the incoming one is not `None`
        if let Some(incoming_accepted_ips) = &mut toml_content.accepted_ips {
            if self.accepted_ips.is_some() {
                self.accepted_ips
                    .as_mut()
                    .unwrap()
                    .append(incoming_accepted_ips);
            } else {
                self.accepted_ips = toml_content.accepted_ips;
            }
        }
        if toml_content.email.is_some() {
            self.email = toml_content.email;
        }
        if toml_content.shell.is_some() {
            self.shell = toml_content.shell;
        }
        if toml_content.shell_args.is_some() {
            self.shell_args = toml_content.shell_args;
        }
        if toml_content.log_file.is_some() {
            self.log_file = toml_content.log_file;
        }
        if toml_content.tmpdir.is_some() {
            self.tmpdir = toml_content.tmpdir;
        }
        if toml_content.mail_host.is_some() {
            self.mail_host = toml_content.mail_host;
        }
        if toml_content.mail_port.is_some() {
            self.mail_port = toml_content.mail_port;
        }
        if toml_content.mail_from.is_some() {
            self.mail_from = toml_content.mail_from;
        }
        if toml_content.mail_passwdcmd.is_some() {
            self.mail_passwdcmd = toml_content.mail_passwdcmd;
        }
        if toml_content.totp_secret.is_some() {
            self.totp_secret = toml_content.totp_secret;
        }
        if toml_content.totp_digits.is_some() {
            self.totp_digits = toml_content.totp_digits;
        }
        if toml_content.totp_timestep.is_some() {
            self.totp_timestep = toml_content.totp_timestep;
        }
        if toml_content.totp_hash.is_some() {
            self.totp_hash = toml_content.totp_hash;
        }
        Ok(())
    }

    /// Load configuration from all designated locations, latter overriding former ones
    pub fn load_all_possible(&mut self) -> io::Result<()> {
        // A warning will be emitted if no configuration is found
        let mut found_any = false;

        for filename in &["/etc/secrc", "/etc/secrc.toml"] {
            if self.load_config(filename).is_ok() {
                found_any = true;
            }
        }
        if let Some(mut home_dir) = home::home_dir() {
            home_dir.push(".secrc");
            if let Some(path_str) = home_dir.to_str() {
                if self.load_config(path_str).is_ok() {
                    found_any = true;
                }
            }
            home_dir.set_extension("toml");
            if let Some(path_str) = home_dir.to_str() {
                if self.load_config(path_str).is_ok() {
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
            .open(&self.log_file.as_ref().ok_or_else(|| {
                Error::new(ErrorKind::Other, "`SecRcCfg.log_file` should not be `None`")
            })?)
    }

    /// Execute the configured shell, replacing the current process
    pub fn execute_shell(&self, mut additional_params: Vec<String>) -> Result<(), String> {
        let mut args: Vec<String> = self
            .shell_args
            .as_ref()
            // self.shell_args must not be None as guaranteed by Default-initialization
            .expect("Bug: `SecRcCfg.shell_args` should never be `None`")
            .split_whitespace()
            .map(std::string::ToString::to_string)
            .collect();
        args.append(&mut additional_params);
        env::set_var("SIB_FROM_IP", get_from());
        let shell = self
            .shell
            .as_ref()
            .ok_or("`SecRcCfg.shell` should not be `None`")?;

        match search_shells(shell) {
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
            Command::new(shell.clone()).args(&args).exec()
        ))
    }
}

impl Default for SecRcCfg {
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

        SecRcCfg {
            accepted_ips: Some(vec![]),
            shell: None,
            /// Default to have no args
            shell_args: Some(String::default()),
            log_file: Some(String::from("/var/log/sibsecsh.log")),
            tmpdir: Some(tmpdir),
            /// None disables this authenticator
            /// Not prefixed by `mail_` for compatibility reason
            email: None,
            mail_host: None,
            mail_port: Some(587),
            mail_from: None,
            mail_passwdcmd: None,
            /// None disables this authenticator
            totp_secret: None,
            totp_digits: Some(6),
            totp_timestep: Some(30),
            totp_hash: Some(String::from("SHA1")),
        }
    }
}

fn search_shells(shell_name: &str) -> io::Result<bool> {
    const SHELLS_FILE: &str = "/etc/shells";
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
