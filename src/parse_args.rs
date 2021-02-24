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
use std::env;

/// Parse command line arguments, the first reture value is the aargument to
/// -c if any, and the second argument is the other arguments
pub fn parse_args() -> (Option<String>, Vec<String>) {
    let all_args: Vec<String> = env::args().map(|x| x.to_string()).collect();
    info!("Program arguments: {:?}", all_args);
    for (i, argument) in env::args().enumerate() {
        if argument == "-c" {
            let mut other: Vec<String> = all_args[1..i].to_vec();
            let mut at_the_back = all_args[i + 2..all_args.len()].to_vec();
            other.append(&mut at_the_back);
            return (Some(all_args[i + 1].clone()), other);
        }
    }
    (None, all_args[1..all_args.len()].to_vec())
}
