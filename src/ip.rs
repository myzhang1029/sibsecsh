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
use regex::Regex;
use std::env;
use subprocess::{Exec, PopenError, Redirection};

/// Get the output of who -u am i
fn read_who_ami() -> Result<String, PopenError> {
    Ok(Exec::cmd("/usr/bin/who")
        .args(&["-u", "am", "i"])
        .stdout(Redirection::Pipe)
        .capture()?
        .stdout_str()
        .trim()
        .to_string())
}

/// Get login source IP address
pub fn get_from_ip() -> String {
    // First try to get the ip from $SSH_CONNECTION
    if let Ok(value) = env::var("SSH_CONNECTION") {
        if let Some(ip_address) = value.split_whitespace().next() {
            return ip_address.to_string();
        }
    }

    // Try to do that with `who`
    if let Ok(value) = read_who_ami() {
        debug!("Command `who -u am i` returned {:?}", value);
        match Regex::new(r"\(.*\)") {
            Ok(ip_re) => {
                if let Some(ip_match) = ip_re.find(&value) {
                    // Remove brackets
                    return value[ip_match.start() + 1..ip_match.end() - 1].to_string();
                }
            }
            Err(e) => debug!("Regular expression failed with error {:?}", e),
        };
    }
    // Else: Most likely a reverse shell login
    String::from("")
}
