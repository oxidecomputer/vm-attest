// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#[cfg(feature = "test-data")]
use anyhow::Context;
use anyhow::Result;

#[cfg(feature = "test-data")]
mod test_data;

/// This path is where Oxide specific libraries live on helios systems.
/// The linker needs this path to find libipcc:
/// https://github.com/oxidecomputer/ipcc-rs/
#[cfg(target_os = "illumos")]
static OXIDE_PLATFORM: &str = "/usr/platform/oxide/lib/amd64/";

fn main() -> Result<()> {
    #[cfg(target_os = "illumos")]
    {
        println!("cargo:rustc-link-arg=-Wl,-R{}", OXIDE_PLATFORM);
        println!("cargo:rustc-link-search={}", OXIDE_PLATFORM);
    }

    #[cfg(feature = "test-data")]
    test_data::generate().context("generate mock data for testing")?;

    Ok(())
}
