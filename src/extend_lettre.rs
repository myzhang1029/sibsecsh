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
