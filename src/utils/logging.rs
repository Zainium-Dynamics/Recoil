/*
 * Copyright (C) 2026 Ali Zain <alizain.arch@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

use tracing_subscriber::{fmt, EnvFilter};

/// Initialise the global tracing subscriber.
///
/// Log level is controlled by the `RECOIL_LOG` environment variable.
/// The default level when the variable is absent is `warn`, which means
/// normal users see no log output during routine operation.
///
/// Example: `RECOIL_LOG=debug sudo recoil setup`
pub fn init() {
    let filter = EnvFilter::try_from_env("RECOIL_LOG").unwrap_or_else(|_| EnvFilter::new("warn"));

    fmt::Subscriber::builder()
        .with_env_filter(filter)
        .with_target(true)
        .compact()
        .init();
}
