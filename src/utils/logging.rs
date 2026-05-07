/*
Copyright (C) 2026 Ali Zain <alizain.arch@gmail.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://gnu.org>.
*/

use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Initialise the global tracing subscriber.
///
/// Log level is controlled by the RECOIL_LOG env var:
///   RECOIL_LOG=debug recoil setup
///
/// Production default is "warn" — users see nothing unless something
/// actually needs their attention.
pub fn init() {
    let filter = EnvFilter::try_from_env("RECOIL_LOG").unwrap_or_else(|_| EnvFilter::new("warn"));

    tracing_subscriber::registry()
        .with(
            fmt::layer()
                .with_target(true)
                .with_level(true)
                .with_ansi(true)
                .compact(),
        )
        .with(filter)
        .init();
}
