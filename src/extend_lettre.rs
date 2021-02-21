use lettre::smtp::client::net::ClientTlsParameters;
use lettre::smtp::client::net::DEFAULT_TLS_PROTOCOLS;
use lettre::smtp::error::Error;
use lettre::smtp::ClientSecurity;
use lettre::SmtpClient;
use native_tls::TlsConnector;

/// Yet another lettre::SmtpClient::new_simple but accepting a custom port.
pub fn new_simple_port(domain: &str, port: u16) -> Result<SmtpClient, Error> {
    let mut tls_builder = TlsConnector::builder();
    tls_builder.min_protocol_version(Some(DEFAULT_TLS_PROTOCOLS[0]));

    let tls_parameters = ClientTlsParameters::new(domain.to_string(), tls_builder.build().unwrap());
    let security = ClientSecurity::Required(tls_parameters);

    SmtpClient::new((domain, port), security)
}
