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
