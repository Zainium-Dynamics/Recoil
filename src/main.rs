/*
Copyright! (C) 2026 Ali Zain <alizain.arch@gmail.com>

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

use clap::Parser;
use console::style;

use recoil::cli::{dispatch, Cli};
use recoil::error::RecoilError;

#[tokio::main]
async fn main() {
    recoil::utils::logging::init();

    let cli = Cli::parse();

    if let Err(e) = dispatch(cli).await {
        print_error(&e);
        std::process::exit(1);
    }
}

/// User-facing error messages.
///
/// We distinguish between errors the user can fix (wrong password, needs root)
/// and errors that are our bug (unexpected I/O, crypto failures).
/// Internal debug information only appears when RECOIL_LOG=debug is set.
fn print_error(e: &RecoilError) {
    match e {
        RecoilError::PermissionDenied => {
            eprintln!(
                "\n  {} This command requires root privileges.\n  Run: {}\n",
                style("✗").red().bold(),
                style("sudo recoil setup").cyan(),
            );
        }
        RecoilError::NotInitialised => {
            eprintln!(
                "\n  {} Recoil is not initialised on this system.\n  Run: {}\n",
                style("✗").red().bold(),
                style("sudo recoil setup").cyan(),
            );
        }
        RecoilError::AuthFailed => {
            eprintln!(
                "\n  {} Authentication failed — wrong master password.\n",
                style("✗").red().bold(),
            );
        }
        RecoilError::RateLimited { minutes } => {
            eprintln!(
                "\n  {} Vault locked — too many failed attempts.\n  \
                 Try again in {} minute(s).\n",
                style("✗").red().bold(),
                style(minutes).yellow(),
            );
        }
        RecoilError::HardLocked => {
            eprintln!(
                "\n  {} Vault is permanently locked due to a sustained \
                 brute-force attack.\n  \
                 Manual administrator reset is required.\n",
                style("✗").red().bold(),
            );
        }
        other => {
            eprintln!(
                "\n  {} Error: {}\n",
                style("✗").red().bold(),
                style(other).dim(),
            );
            tracing::debug!(?other, "Full error detail");
        }
    }
}
