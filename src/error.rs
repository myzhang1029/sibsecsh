/// Wait for user input before panic!king.
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
#[macro_export]
macro_rules! panic_gracefully {
    () => ({ $crate::panic_gracefully!("explicit panic") });
    ($msg:expr $(,)?) => ({
        eprintln!($msg);
        std::io::stdin().read_line(&mut String::new()).unwrap();
        panic!($msg);
    });
    ($fmt:expr, $($arg:tt)+) => ({
        eprintln!($fmt, $($arg)+);
        std::io::stdin().read_line(&mut String::new()).unwrap();
        panic!($fmt, $($arg)+);
    });
}
