use crate::config::Config;
use crate::ip::get_from_ip;
use ipaddress::IPAddress;

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
    fn is_accepted_login(&self) -> Option<bool>;
    /// Check if the execute request is accepted by this authenticator
    /// The modified (if any) command line is put back into cmd
    /// i.e. when -c cmdline is supplied
    fn is_accepted_exec(&self, cmd: &mut String) -> Option<bool>;
}

pub struct LocalIPAuthenticator<'a> {
    config: &'a Config,
}

impl<'a> Authenticator<'a> for LocalIPAuthenticator<'a> {
    fn init(config: &'a Config) -> Self {
        LocalIPAuthenticator { config: config }
    }

    fn is_accepted_login(&self) -> Option<bool> {
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
                warn!("Local login accepted");
                return Some(true);
            }
        }
        None
    }

    fn is_accepted_exec(&self, _cmd: &mut String) -> Option<bool> {
        self.is_accepted_login()
    }
}

pub struct BypassAuthenticator {}

impl Authenticator<'_> for BypassAuthenticator {
    fn init(_config: &Config) -> Self {
        BypassAuthenticator {}
    }

    fn is_accepted_login(&self) -> Option<bool> {
        if let Some(mut home_dir) = home::home_dir() {
            home_dir.push("NoSec");
            if home_dir.exists() {
                warn!("Sibsecsh turned off");
                return Some(true);
            }
        }
        if let Ok(_value) = std::env::var("SIB_FROM_IP") {
            warn!("Nested login accepted");
            return Some(true);
        }
        None
    }

    fn is_accepted_exec(&self, _cmd: &mut String) -> Option<bool> {
        self.is_accepted_login()
    }
}
